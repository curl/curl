/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * Trivial file transfer protocol server.
 *
 * This code includes many modifications by Jim Guyton <guyton@rand-unix>
 *
 * This source file was started based on netkit-tftpd 0.17
 * Heavily modified for curl's test suite
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "setup.h" /* portability help from the lib directory */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <signal.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_TFTP_H
#include <arpa/tftp.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_FILIO_H
/* FIONREAD on Solaris 7 */
#include <sys/filio.h>
#endif

#include <setjmp.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "getpart.h"
#include "util.h"

struct testcase {
  char *buffer;   /* holds the file data to send to the client */
  size_t bufsize; /* size of the data in buffer */
  char *rptr;     /* read pointer into the buffer */
  size_t rcount;  /* amount of data left to read of the file */
  long num;       /* test case number */
  int ofile;      /* file descriptor for output file when uploading to us */
  FILE *server;   /* write input "protocol" there for client verification */
};

static int synchnet(int);
static struct tftphdr *r_init(void);
static struct tftphdr *w_init(void);
static int readit(struct testcase *test, struct tftphdr **dpp, int convert);
static int writeit(struct testcase *test, struct tftphdr **dpp, int ct,
                   int convert);
static void mysignal(int, void (*func)(int));


#define TIMEOUT         5

#define PKTSIZE SEGSIZE+4

struct formats;
static int tftp(struct testcase *test, struct tftphdr *tp, int size);
static void nak(int error);
static void sendfile(struct testcase *test, struct formats *pf);
static void recvfile(struct testcase *test, struct formats *pf);
static int validate_access(struct testcase *test, const char *, int);

static curl_socket_t peer;
static int rexmtval = TIMEOUT;
static int maxtimeout = 5*TIMEOUT;

static char buf[PKTSIZE];
static char ackbuf[PKTSIZE];
static struct sockaddr_in from;
static socklen_t fromlen;

struct bf {
  int counter;            /* size of data in buffer, or flag */
  char buf[PKTSIZE];      /* room for data packet */
} bfs[2];

                                /* Values for bf.counter  */
#define BF_ALLOC -3             /* alloc'd but not yet filled */
#define BF_FREE  -2             /* free */
/* [-1 .. SEGSIZE] = size of data in the data buffer */

static int nextone;     /* index of next buffer to use */
static int current;     /* index of buffer in use */

                        /* control flags for crlf conversions */
int newline = 0;        /* fillbuf: in middle of newline expansion */
int prevchar = -1;      /* putbuf: previous char (cr check) */

static void read_ahead(struct testcase *test,
                       int convert /* if true, convert to ascii */);
static int write_behind(struct testcase *test, int convert);
static struct tftphdr *rw_init(int);
static struct tftphdr *w_init(void) { return rw_init(0); } /* write-behind */
static struct tftphdr *r_init(void) { return rw_init(1); } /* read-ahead */

static struct tftphdr *
rw_init(int x)              /* init for either read-ahead or write-behind */
{                           /* zero for write-behind, one for read-head */
  newline = 0;            /* init crlf flag */
  prevchar = -1;
  bfs[0].counter =  BF_ALLOC;     /* pass out the first buffer */
  current = 0;
  bfs[1].counter = BF_FREE;
  nextone = x;                    /* ahead or behind? */
  return (struct tftphdr *)bfs[0].buf;
}


/* Have emptied current buffer by sending to net and getting ack.
   Free it and return next buffer filled with data.
 */
static int readit(struct testcase *test, struct tftphdr **dpp,
           int convert /* if true, convert to ascii */)
{
  struct bf *b;

  bfs[current].counter = BF_FREE; /* free old one */
  current = !current;             /* "incr" current */

  b = &bfs[current];              /* look at new buffer */
  if (b->counter == BF_FREE)      /* if it's empty */
    read_ahead(test, convert);      /* fill it */

  *dpp = (struct tftphdr *)b->buf;        /* set caller's ptr */
  return b->counter;
}

#define MIN(x,y) ((x)<(y)?(x):(y));

/*
 * fill the input buffer, doing ascii conversions if requested
 * conversions are  lf -> cr,lf  and cr -> cr, nul
 */
static void read_ahead(struct testcase *test,
                       int convert /* if true, convert to ascii */)
{
  int i;
  char *p;
  int c;
  struct bf *b;
  struct tftphdr *dp;

  b = &bfs[nextone];              /* look at "next" buffer */
  if (b->counter != BF_FREE)      /* nop if not free */
    return;
  nextone = !nextone;             /* "incr" next buffer ptr */

  dp = (struct tftphdr *)b->buf;

  if (convert == 0) {
    /* The former file reading code did this:
       b->counter = read(fileno(file), dp->th_data, SEGSIZE); */
    int copy_n = MIN(SEGSIZE, test->rcount);
    memcpy(dp->th_data, test->rptr, copy_n);

    /* decrease amount, advance pointer */
    test->rcount -= copy_n;
    test->rptr += copy_n;
    b->counter = copy_n;
    return;
  }

  p = dp->th_data;
  for (i = 0 ; i < SEGSIZE; i++) {
    if (newline) {
      if (prevchar == '\n')
        c = '\n';       /* lf to cr,lf */
      else
        c = '\0';       /* cr to cr,nul */
      newline = 0;
    }
    else {
      if(test->rcount) {
        c=test->rptr[0];
        test->rptr++;
        test->rcount--;
      }
      else
        break;
      if (c == '\n' || c == '\r') {
        prevchar = c;
        c = '\r';
        newline = 1;
      }
    }
    *p++ = c;
  }
  b->counter = (int)(p - dp->th_data);
}

/* Update count associated with the buffer, get new buffer from the queue.
   Calls write_behind only if next buffer not available.
 */
static int writeit(struct testcase *test, struct tftphdr **dpp,
                   int ct, int convert)
{
  bfs[current].counter = ct;      /* set size of data to write */
  current = !current;             /* switch to other buffer */
  if (bfs[current].counter != BF_FREE)     /* if not free */
    write_behind(test, convert);     /* flush it */
  bfs[current].counter = BF_ALLOC;        /* mark as alloc'd */
  *dpp =  (struct tftphdr *)bfs[current].buf;
  return ct;                      /* this is a lie of course */
}

/*
 * Output a buffer to a file, converting from netascii if requested.
 * CR,NUL -> CR  and CR,LF => LF.
 * Note spec is undefined if we get CR as last byte of file or a
 * CR followed by anything else.  In this case we leave it alone.
 */
static int write_behind(struct testcase *test, int convert)
{
  char *buf;
  int count;
  int ct;
  char *p;
  int c;                          /* current character */
  struct bf *b;
  struct tftphdr *dp;

  b = &bfs[nextone];
  if (b->counter < -1)            /* anything to flush? */
    return 0;                     /* just nop if nothing to do */

  if(!test->ofile) {
    char outfile[256];
    snprintf(outfile, sizeof(outfile), "log/upload.%ld", test->num);
    test->ofile=open(outfile, O_CREAT|O_RDWR, 0777);
    if(test->ofile == -1) {
      logmsg("Couldn't create and/or open file %s for upload!", outfile);
      return -1; /* failure! */
    }
  }

  count = b->counter;             /* remember byte count */
  b->counter = BF_FREE;           /* reset flag */
  dp = (struct tftphdr *)b->buf;
  nextone = !nextone;             /* incr for next time */
  buf = dp->th_data;

  if (count <= 0)
    return -1;                    /* nak logic? */

  if (convert == 0)
    return write(test->ofile, buf, count);

  p = buf;
  ct = count;
  while (ct--) {                  /* loop over the buffer */
    c = *p++;                     /* pick up a character */
    if (prevchar == '\r') {       /* if prev char was cr */
      if (c == '\n')              /* if have cr,lf then just */
        lseek(test->ofile, -1, SEEK_CUR); /* smash lf on top of the cr */
      else
        if (c == '\0')            /* if have cr,nul then */
          goto skipit;            /* just skip over the putc */
      /* else just fall through and allow it */
    }
    /* formerly
       putc(c, file); */
    write(test->ofile, &c, 1);
    skipit:
    prevchar = c;
  }
  return count;
}


/* When an error has occurred, it is possible that the two sides are out of
 * synch.  Ie: that what I think is the other side's response to packet N is
 * really their response to packet N-1.
 *
 * So, to try to prevent that, we flush all the input queued up for us on the
 * network connection on our host.
 *
 * We return the number of packets we flushed (mostly for reporting when trace
 * is active).
 */

static int synchnet(curl_socket_t f /* socket to flush */)
{
  int i, j = 0;
  char rbuf[PKTSIZE];
  struct sockaddr_in from;
  socklen_t fromlen;

  while (1) {
    (void) ioctl(f, FIONREAD, &i);
    if (i) {
      j++;
      fromlen = sizeof from;
      (void) recvfrom(f, rbuf, sizeof (rbuf), 0,
                      (struct sockaddr *)&from, &fromlen);
    }
    else
      return j;
  }
}

/*
 * Like signal(), but with well-defined semantics.
 */
static void mysignal(int sig, void (*handler)(int))
{
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigaction(sig, &sa, NULL);
}


#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/tftpd.log"
#endif

#define DEFAULT_PORT 8999 /* UDP */
const char *serverlogfile = DEFAULT_LOGFILE;

#define REQUEST_DUMP  "log/server.input"

char use_ipv6=FALSE;

int main(int argc, char **argv)
{
  struct sockaddr_in me;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 me6;
#endif /* ENABLE_IPV6 */

  struct tftphdr *tp;
  int n = 0;
  int arg = 1;
  FILE *pidfile;
  char *pidname= (char *)".tftpd.pid";
  unsigned short port = DEFAULT_PORT;
  curl_socket_t sock;
  int flag;
  int rc;
  struct testcase test;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("tftpd IPv4%s\n",
#ifdef ENABLE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef ENABLE_IPV6
      use_ipv6=TRUE;
#endif
      arg++;
    }
    else if(argc>arg) {

      if(atoi(argv[arg]))
        port = (unsigned short)atoi(argv[arg++]);

      if(argc>arg)
        path = argv[arg++];
    }
  }

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
  win32_init();
  atexit(win32_cleanup);
#endif

#ifdef ENABLE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef ENABLE_IPV6
  else
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
#endif

  if (sock < 0) {
    perror("opening stream socket");
    logmsg("Error opening socket");
    exit(1);
  }

  flag = 1;
  if (setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &flag,
       sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR)");
  }

#ifdef ENABLE_IPV6
  if(!use_ipv6) {
#endif
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(port);
    rc = bind(sock, (struct sockaddr *) &me, sizeof(me));
#ifdef ENABLE_IPV6
  }
  else {
    memset(&me6, 0, sizeof(struct sockaddr_in6));
    me6.sin6_family = AF_INET6;
    me6.sin6_addr = in6addr_any;
    me6.sin6_port = htons(port);
    rc = bind(sock, (struct sockaddr *) &me6, sizeof(me6));
  }
#endif /* ENABLE_IPV6 */
  if(rc < 0) {
    perror("binding stream socket");
    logmsg("Error binding socket");
    exit(1);
  }

  pidfile = fopen(pidname, "w");
  if(pidfile) {
    fprintf(pidfile, "%d\n", (int)getpid());
    fclose(pidfile);
  }
  else
    fprintf(stderr, "Couldn't write pid file\n");

  logmsg("Running IPv%d version on port UDP/%d",
#ifdef ENABLE_IPV6
         (use_ipv6?6:4)
#else
         4
#endif
         , port );

  do {
    FILE *server;

    server = fopen(REQUEST_DUMP, "ab");
    if(!server)
      break;

    fromlen = sizeof(from);
    n = recvfrom(sock, buf, sizeof (buf), 0,
                 (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
      logmsg("recvfrom:\n");
      return 3;
    }

    from.sin_family = AF_INET;

    peer = socket(AF_INET, SOCK_DGRAM, 0);
    if (peer < 0) {
      logmsg("socket:\n");
      return 2;
    }

    if (connect(peer, (struct sockaddr *)&from, sizeof(from)) < 0) {
      logmsg("connect: fail\n");
      return 1;
    }

    tp = (struct tftphdr *)buf;
    tp->th_opcode = ntohs(tp->th_opcode);
    if (tp->th_opcode == RRQ || tp->th_opcode == WRQ) {
      memset(&test, 0, sizeof(test));
      test.server = server;
      tftp(&test, tp, n);
    }
    fclose(server);
    sclose(peer);
  } while(1);
  return 0;
}

struct formats {
  const char *f_mode;
  int f_convert;
} formats[] = {
  { "netascii",   1 },
  { "octet",      0 },
  { NULL,         0 }
};

/*
 * Handle initial connection protocol.
 */
static int tftp(struct testcase *test, struct tftphdr *tp, int size)
{
  char *cp;
  int first = 1, ecode;
  struct formats *pf;
  char *filename, *mode = NULL;

  /* store input protocol */
  fprintf(test->server, "opcode: %x\n", tp->th_opcode);

  filename = cp = tp->th_stuff;
again:
  while (cp < buf + size) {
    if (*cp == '\0')
      break;
    cp++;
  }
  if (*cp) {
    nak(EBADOP);
    return 3;
  }
  if (first) {
    mode = ++cp;
    first = 0;
    goto again;
  }
  /* store input protocol */
  fprintf(test->server, "filename: %s\n", filename);

  for (cp = mode; *cp; cp++)
    if (isupper(*cp))
      *cp = tolower(*cp);

  /* store input protocol */
  fprintf(test->server, "mode: %s\n", mode);

  for (pf = formats; pf->f_mode; pf++)
    if (strcmp(pf->f_mode, mode) == 0)
      break;
  if (!pf->f_mode) {
    nak(EBADOP);
    return 2;
  }
  ecode = validate_access(test, filename, tp->th_opcode);
  if (ecode) {
    nak(ecode);
    return 1;
  }
  if (tp->th_opcode == WRQ)
    recvfile(test, pf);
  else
    sendfile(test, pf);
  return 0;
}

/*
 * Validate file access.
 */
static int validate_access(struct testcase *test,
                           const char *filename, int mode)
{
  char *ptr;
  long testno;

  logmsg("trying to get file: %s mode %x", filename, mode);

  if(!strncmp("/verifiedserver", filename, 15)) {
    char weare[128];
    size_t count = sprintf(weare, "WE ROOLZ: %d\r\n", (int)getpid());

    logmsg("Are-we-friendly question received");
    test->buffer = strdup(weare);
    test->rptr = test->buffer; /* set read pointer */
    test->bufsize = count;    /* set total count */
    test->rcount = count;     /* set data left to read */
    return 0; /* fine */
  }

  /* find the last slash */
  ptr = strrchr(filename, '/');

  if(ptr) {
    char *file;

    ptr++; /* skip the slash */

    /* skip all non-numericals following the slash */
    while(*ptr && !isdigit((int)*ptr))
      ptr++;

    /* get the number */
    testno = strtol(ptr, &ptr, 10);

    logmsg("requested test number %d", testno);

    test->num = testno;

    file = test2file(testno);

    if(file) {
      FILE *stream=fopen(file, "rb");
      if(!stream) {
        logmsg("Couldn't open test file: %s", file);
        return EACCESS;
      }
      else {
        size_t count;
        test->buffer = (char *)spitout(stream, "reply", "data", &count);
        fclose(stream);
        if(test->buffer) {
          test->rptr = test->buffer; /* set read pointer */
          test->bufsize = count;    /* set total count */
          test->rcount = count;     /* set data left to read */
        }
        else
          return EACCESS;
      }

    }
    else
      return EACCESS;
  }
  else {
    logmsg("no slash found in path");
    return EACCESS; /* failure */
  }

  return 0;
}

int timeout;
sigjmp_buf timeoutbuf;

static void timer(int signum)
{
  (void)signum;

  timeout += rexmtval;
  if (timeout >= maxtimeout)
    exit(1);
  siglongjmp(timeoutbuf, 1);
}

/*
 * Send the requested file.
 */
static void sendfile(struct testcase *test, struct formats *pf)
{
  struct tftphdr *dp;
  struct tftphdr *ap;    /* ack packet */
  unsigned short block = 1;
  int size, n;

  mysignal(SIGALRM, timer);
  dp = r_init();
  ap = (struct tftphdr *)ackbuf;
  do {
    size = readit(test, &dp, pf->f_convert);
    if (size < 0) {
      nak(errno + 100);
      goto abort;
    }
    dp->th_opcode = htons((u_short)DATA);
    dp->th_block = htons((u_short)block);
    timeout = 0;
    (void) sigsetjmp(timeoutbuf, 1);

    send_data:
    if (send(peer, dp, size + 4, 0) != size + 4) {
      logmsg("write\n");
      goto abort;
    }
    read_ahead(test, pf->f_convert);
    for ( ; ; ) {
      alarm(rexmtval);        /* read the ack */
      n = recv(peer, ackbuf, sizeof (ackbuf), 0);
      alarm(0);
      if (n < 0) {
        logmsg("read: fail\n");
        goto abort;
      }
      ap->th_opcode = ntohs((u_short)ap->th_opcode);
      ap->th_block = ntohs((u_short)ap->th_block);

      if (ap->th_opcode == ERROR)
        goto abort;

      if (ap->th_opcode == ACK) {
        if (ap->th_block == block) {
          break;
        }
        /* Re-synchronize with the other side */
        (void) synchnet(peer);
        if (ap->th_block == (block -1)) {
          goto send_data;
        }
      }

    }
    block++;
  } while (size == SEGSIZE);
  abort:
  ;
}

static void justquit(int signum)
{
  (void)signum;
  exit(0);
}


/*
 * Receive a file.
 */
static void recvfile(struct testcase *test, struct formats *pf)
{
  struct tftphdr *dp;
  struct tftphdr *ap;    /* ack buffer */
  unsigned short block = 0;
  int n, size;

  mysignal(SIGALRM, timer);
  dp = w_init();
  ap = (struct tftphdr *)ackbuf;
  do {
    timeout = 0;
    ap->th_opcode = htons((u_short)ACK);
    ap->th_block = htons((u_short)block);
    block++;
    (void) sigsetjmp(timeoutbuf, 1);
send_ack:
    if (send(peer, ackbuf, 4, 0) != 4) {
      logmsg("write: fail\n");
      goto abort;
    }
    write_behind(test, pf->f_convert);
    for ( ; ; ) {
      alarm(rexmtval);
      n = recv(peer, dp, PKTSIZE, 0);
      alarm(0);
      if (n < 0) {                       /* really? */
        logmsg("read: fail\n");
        goto abort;
      }
      dp->th_opcode = ntohs((u_short)dp->th_opcode);
      dp->th_block = ntohs((u_short)dp->th_block);
      if (dp->th_opcode == ERROR)
        goto abort;
      if (dp->th_opcode == DATA) {
        if (dp->th_block == block) {
          break;                         /* normal */
        }
        /* Re-synchronize with the other side */
        (void) synchnet(peer);
        if (dp->th_block == (block-1))
          goto send_ack;                 /* rexmit */
      }
    }

    size = writeit(test, &dp, n - 4, pf->f_convert);
    if (size != (n-4)) {                 /* ahem */
      if (size < 0)
        nak(errno + 100);
      else
        nak(ENOSPACE);
      goto abort;
    }
  } while (size == SEGSIZE);
  write_behind(test, pf->f_convert);

  ap->th_opcode = htons((u_short)ACK);   /* send the "final" ack */
  ap->th_block = htons((u_short)(block));
  (void) send(peer, ackbuf, 4, 0);

  mysignal(SIGALRM, justquit);           /* just quit on timeout */
  alarm(rexmtval);
  n = recv(peer, buf, sizeof (buf), 0);  /* normally times out and quits */
  alarm(0);
  if (n >= 4 &&                          /* if read some data */
      dp->th_opcode == DATA &&           /* and got a data block */
      block == dp->th_block) {           /* then my last ack was lost */
    (void) send(peer, ackbuf, 4, 0);     /* resend final ack */
  }
abort:
  return;
}

struct errmsg {
  int e_code;
  const char *e_msg;
} errmsgs[] = {
  { EUNDEF,       "Undefined error code" },
  { ENOTFOUND,    "File not found" },
  { EACCESS,      "Access violation" },
  { ENOSPACE,     "Disk full or allocation exceeded" },
  { EBADOP,       "Illegal TFTP operation" },
  { EBADID,       "Unknown transfer ID" },
  { EEXISTS,      "File already exists" },
  { ENOUSER,      "No such user" },
  { -1,           0 }
};

/*
 * Send a nak packet (error message).  Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno offset by 100.
 */
static void nak(int error)
{
  struct tftphdr *tp;
  int length;
  struct errmsg *pe;

  tp = (struct tftphdr *)buf;
  tp->th_opcode = htons((u_short)ERROR);
  tp->th_code = htons((u_short)error);
  for (pe = errmsgs; pe->e_code >= 0; pe++)
    if (pe->e_code == error)
      break;
  if (pe->e_code < 0) {
    pe->e_msg = strerror(error - 100);
    tp->th_code = EUNDEF;   /* set 'undef' errorcode */
  }
  strcpy(tp->th_msg, pe->e_msg);
  length = strlen(pe->e_msg);
  tp->th_msg[length] = '\0';
  length += 5;
  if (send(peer, buf, length, 0) != length)
    logmsg("nak: fail\n");
}
