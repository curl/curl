/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* Purpose
 *
 * 1. Accept a TCP connection on a custom port (ipv4 or ipv6), or connect
 *    to a given (localhost) port.
 *
 * 2. Get commands on STDIN. Pass data on to the TCP stream.
 *    Get data from TCP stream and pass on to STDOUT.
 *
 * This program is made to perform all the socket/stream/connection stuff for
 * the test suite's (perl) FTP server. Previously the perl code did all of
 * this by its own, but I decided to let this program do the socket layer
 * because of several things:
 *
 * o We want the perl code to work with rather old perl installations, thus
 *   we cannot use recent perl modules or features.
 *
 * o We want IPv6 support for systems that provide it, and doing optional IPv6
 *   support in perl seems if not impossible so at least awkward.
 *
 * o We want FTP-SSL support, which means that a connection that starts with
 *   plain sockets needs to be able to "go SSL" in the midst. This would also
 *   require some nasty perl stuff I'd rather avoid.
 *
 * (Source originally based on sws.c)
 */

/*
 * Signal handling notes for sockfilt
 * ----------------------------------
 *
 * This program is a single-threaded process.
 *
 * This program is intended to be highly portable and as such it must be kept as
 * simple as possible, due to this the only signal handling mechanisms used will
 * be those of ANSI C, and used only in the most basic form which is good enough
 * for the purpose of this program.
 *
 * For the above reason and the specific needs of this program signals SIGHUP,
 * SIGPIPE and SIGALRM will be simply ignored on systems where this can be done.
 * If possible, signals SIGINT and SIGTERM will be handled by this program as an
 * indication to cleanup and finish execution as soon as possible.  This will be
 * achieved with a single signal handler 'exit_signal_handler' for both signals.
 *
 * The 'exit_signal_handler' upon the first SIGINT or SIGTERM received signal
 * will just set to one the global var 'got_exit_signal' storing in global var
 * 'exit_signal' the signal that triggered this change.
 *
 * Nothing fancy that could introduce problems is used, the program at certain
 * points in its normal flow checks if var 'got_exit_signal' is set and in case
 * this is true it just makes its way out of loops and functions in structured
 * and well behaved manner to achieve proper program cleanup and termination.
 *
 * Even with the above mechanism implemented it is worthwile to note that other
 * signals might still be received, or that there might be systems on which it
 * is not possible to trap and ignore some of the above signals.  This implies
 * that for increased portability and reliability the program must be coded as
 * if no signal was being ignored or handled at all.  Enjoy it!
 */

#define CURL_NO_OLDIES

#include "setup.h" /* portability help from the lib directory */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "inet_pton.h"
#include "util.h"

/* include memdebug.h last */
#include "memdebug.h"

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sockfilt.log"
#endif

const char *serverlogfile = DEFAULT_LOGFILE;

static bool verbose = FALSE;
#ifdef ENABLE_IPV6
static bool use_ipv6 = FALSE;
#endif
static const char *ipv_inuse = "IPv4";
static unsigned short port = DEFAULT_PORT;
static unsigned short connectport = 0; /* if non-zero, we activate this mode */

enum sockmode {
  PASSIVE_LISTEN,    /* as a server waiting for connections */
  PASSIVE_CONNECT,   /* as a server, connected to a client */
  ACTIVE,            /* as a client, connected to a server */
  ACTIVE_DISCONNECT  /* as a client, disconnected from server */
};

/* do-nothing macro replacement for systems which lack siginterrupt() */

#ifndef HAVE_SIGINTERRUPT
#define siginterrupt(x,y) do {} while(0)
#endif

/* vars used to keep around previous signal handlers */

typedef RETSIGTYPE (*SIGHANDLER_T)(int);

#ifdef SIGHUP
static SIGHANDLER_T old_sighup_handler  = SIG_ERR;
#endif

#ifdef SIGPIPE
static SIGHANDLER_T old_sigpipe_handler = SIG_ERR;
#endif

#ifdef SIGALRM
static SIGHANDLER_T old_sigalrm_handler = SIG_ERR;
#endif

#ifdef SIGINT
static SIGHANDLER_T old_sigint_handler  = SIG_ERR;
#endif

#ifdef SIGTERM
static SIGHANDLER_T old_sigterm_handler = SIG_ERR;
#endif

/* var which if set indicates that the program should finish execution */

SIG_ATOMIC_T got_exit_signal = 0;

/* if next is set indicates the first signal handled in exit_signal_handler */

static volatile int exit_signal = 0;

/* signal handler that will be triggered to indicate that the program
  should finish its execution in a controlled manner as soon as possible.
  The first time this is called it will set got_exit_signal to one and
  store in exit_signal the signal that triggered its execution. */

static RETSIGTYPE exit_signal_handler(int signum)
{
  int old_errno = ERRNO;
  if(got_exit_signal == 0) {
    got_exit_signal = 1;
    exit_signal = signum;
  }
  (void)signal(signum, exit_signal_handler);
  SET_ERRNO(old_errno);
}

static void install_signal_handlers(void)
{
#ifdef SIGHUP
  /* ignore SIGHUP signal */
  if((old_sighup_handler = signal(SIGHUP, SIG_IGN)) == SIG_ERR)
    logmsg("cannot install SIGHUP handler: %s", strerror(ERRNO));
#endif
#ifdef SIGPIPE
  /* ignore SIGPIPE signal */
  if((old_sigpipe_handler = signal(SIGPIPE, SIG_IGN)) == SIG_ERR)
    logmsg("cannot install SIGPIPE handler: %s", strerror(ERRNO));
#endif
#ifdef SIGALRM
  /* ignore SIGALRM signal */
  if((old_sigalrm_handler = signal(SIGALRM, SIG_IGN)) == SIG_ERR)
    logmsg("cannot install SIGALRM handler: %s", strerror(ERRNO));
#endif
#ifdef SIGINT
  /* handle SIGINT signal with our exit_signal_handler */
  if((old_sigint_handler = signal(SIGINT, exit_signal_handler)) == SIG_ERR)
    logmsg("cannot install SIGINT handler: %s", strerror(ERRNO));
  else
    siginterrupt(SIGINT, 1);
#endif
#ifdef SIGTERM
  /* handle SIGTERM signal with our exit_signal_handler */
  if((old_sigterm_handler = signal(SIGTERM, exit_signal_handler)) == SIG_ERR)
    logmsg("cannot install SIGTERM handler: %s", strerror(ERRNO));
  else
    siginterrupt(SIGTERM, 1);
#endif
}

static void restore_signal_handlers(void)
{
#ifdef SIGHUP
  if(SIG_ERR != old_sighup_handler)
    (void)signal(SIGHUP, old_sighup_handler);
#endif
#ifdef SIGPIPE
  if(SIG_ERR != old_sigpipe_handler)
    (void)signal(SIGPIPE, old_sigpipe_handler);
#endif
#ifdef SIGALRM
  if(SIG_ERR != old_sigalrm_handler)
    (void)signal(SIGALRM, old_sigalrm_handler);
#endif
#ifdef SIGINT
  if(SIG_ERR != old_sigint_handler)
    (void)signal(SIGINT, old_sigint_handler);
#endif
#ifdef SIGTERM
  if(SIG_ERR != old_sigterm_handler)
    (void)signal(SIGTERM, old_sigterm_handler);
#endif
}

/*
 * fullread is a wrapper around the read() function. This will repeat the call
 * to read() until it actually has read the complete number of bytes indicated
 * in nbytes or it fails with a condition that cannot be handled with a simple
 * retry of the read call.
 */

static ssize_t fullread(int filedes, void *buffer, size_t nbytes)
{
  int error;
  ssize_t rc;
  ssize_t nread = 0;

  do {
    rc = read(filedes, (unsigned char *)buffer + nread, nbytes - nread);

    if(got_exit_signal) {
      logmsg("signalled to die");
      return -1;
    }

    if(rc < 0) {
      error = ERRNO;
      if((error == EINTR) || (error == EAGAIN))
        continue;
      logmsg("unrecoverable read() failure: %s", strerror(error));
      return -1;
    }

    if(rc == 0) {
      logmsg("got 0 reading from stdin");
      return 0;
    }

    nread += rc;

  } while((size_t)nread < nbytes);

  if(verbose)
    logmsg("read %zd bytes", nread);

  return nread;
}

/*
 * fullwrite is a wrapper around the write() function. This will repeat the
 * call to write() until it actually has written the complete number of bytes
 * indicated in nbytes or it fails with a condition that cannot be handled
 * with a simple retry of the write call.
 */

static ssize_t fullwrite(int filedes, const void *buffer, size_t nbytes)
{
  int error;
  ssize_t wc;
  ssize_t nwrite = 0;

  do {
    wc = write(filedes, (unsigned char *)buffer + nwrite, nbytes - nwrite);

    if(got_exit_signal) {
      logmsg("signalled to die");
      return -1;
    }

    if(wc < 0) {
      error = ERRNO;
      if((error == EINTR) || (error == EAGAIN))
        continue;
      logmsg("unrecoverable write() failure: %s", strerror(error));
      return -1;
    }

    if(wc == 0) {
      logmsg("put 0 writing to stdout");
      return 0;
    }

    nwrite += wc;

  } while((size_t)nwrite < nbytes);

  if(verbose)
    logmsg("wrote %zd bytes", nwrite);

  return nwrite;
}

/*
 * read_stdin tries to read from stdin nbytes into the given buffer. This is a
 * blocking function that will only return TRUE when nbytes have actually been
 * read or FALSE when an unrecoverable error has been detected. Failure of this
 * function is an indication that the sockfilt process should terminate.
 */

static bool read_stdin(void *buffer, size_t nbytes)
{
  ssize_t nread = fullread(fileno(stdin), buffer, nbytes);
  if(nread != (ssize_t)nbytes) {
    logmsg("exiting...");
    return FALSE;
  }
  return TRUE;
}

/*
 * write_stdout tries to write to stdio nbytes from the given buffer. This is a
 * blocking function that will only return TRUE when nbytes have actually been
 * written or FALSE when an unrecoverable error has been detected. Failure of
 * this function is an indication that the sockfilt process should terminate.
 */

static bool write_stdout(const void *buffer, size_t nbytes)
{
  ssize_t nwrite = fullwrite(fileno(stdout), buffer, nbytes);
  if(nwrite != (ssize_t)nbytes) {
    logmsg("exiting...");
    return FALSE;
  }
  return TRUE;
}

static void lograw(unsigned char *buffer, ssize_t len)
{
  char data[120];
  ssize_t i;
  unsigned char *ptr = buffer;
  char *optr = data;
  ssize_t width=0;

  for(i=0; i<len; i++) {
    switch(ptr[i]) {
    case '\n':
      sprintf(optr, "\\n");
      width += 2;
      optr += 2;
      break;
    case '\r':
      sprintf(optr, "\\r");
      width += 2;
      optr += 2;
      break;
    default:
      sprintf(optr, "%c", (ISGRAPH(ptr[i]) || ptr[i]==0x20) ?ptr[i]:'.');
      width++;
      optr++;
      break;
    }

    if(width>60) {
      logmsg("'%s'", data);
      width = 0;
      optr = data;
    }
  }
  if(width)
    logmsg("'%s'", data);
}

/*
  sockfdp is a pointer to an established stream or CURL_SOCKET_BAD

  if sockfd is CURL_SOCKET_BAD, listendfd is a listening socket we must
  accept()
*/
static bool juggle(curl_socket_t *sockfdp,
                   curl_socket_t listenfd,
                   enum sockmode *mode)
{
  struct timeval timeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t sockfd = CURL_SOCKET_BAD;
  curl_socket_t maxfd = CURL_SOCKET_BAD;
  ssize_t rc;
  ssize_t nread_socket;
  ssize_t bytes_written;
  ssize_t buffer_len;
  int error = 0;

 /* 'buffer' is this excessively large only to be able to support things like
    test 1003 which tests exceedingly large server response lines */
  unsigned char buffer[17010];
  char data[16];

  if(got_exit_signal) {
    logmsg("signalled to die, exiting...");
    return FALSE;
  }

#ifdef HAVE_GETPPID
  /* As a last resort, quit if sockfilt process becomes orphan. Just in case
     parent ftpserver process has died without killing its sockfilt children */
  if(getppid() <= 1) {
    logmsg("process becomes orphan, exiting");
    return FALSE;
  }
#endif

  timeout.tv_sec = 120;
  timeout.tv_usec = 0;

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);

#ifdef USE_WINSOCK
  /*
  ** WinSock select() does not support standard file descriptors,
  ** it can only check SOCKETs. Since this program in its current
  ** state will not work on WinSock based systems, next line is
  ** commented out to allow warning-free compilation awaiting the
  ** day it will be fixed to also run on WinSock systems.
  */
#else
  FD_SET(fileno(stdin), &fds_read);
#endif

  switch(*mode) {

  case PASSIVE_LISTEN:

    /* server mode */
    sockfd = listenfd;
    /* there's always a socket to wait for */
    FD_SET(sockfd, &fds_read);
    maxfd = sockfd;
    break;

  case PASSIVE_CONNECT:

    sockfd = *sockfdp;
    if(CURL_SOCKET_BAD == sockfd) {
      /* eeek, we are supposedly connected and then this cannot be -1 ! */
      logmsg("socket is -1! on %s:%d", __FILE__, __LINE__);
      maxfd = 0; /* stdin */
    }
    else {
      /* there's always a socket to wait for */
      FD_SET(sockfd, &fds_read);
      maxfd = sockfd;
    }
    break;

  case ACTIVE:

    sockfd = *sockfdp;
    /* sockfd turns CURL_SOCKET_BAD when our connection has been closed */
    if(CURL_SOCKET_BAD != sockfd) {
      FD_SET(sockfd, &fds_read);
      maxfd = sockfd;
    }
    else {
      logmsg("No socket to read on");
      maxfd = 0;
    }
    break;

  case ACTIVE_DISCONNECT:

    logmsg("disconnected, no socket to read on");
    maxfd = 0;
    sockfd = CURL_SOCKET_BAD;
    break;

  } /* switch(*mode) */


  do {

    rc = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, &timeout);

    if(got_exit_signal) {
      logmsg("signalled to die, exiting...");
      return FALSE;
    }

  } while((rc == -1) && ((error = SOCKERRNO) == EINTR));

  if(rc < 0) {
    logmsg("select() failed with error: (%d) %s",
           error, strerror(error));
    return FALSE;
  }

  if(rc == 0)
    /* timeout */
    return TRUE;


  if(FD_ISSET(fileno(stdin), &fds_read)) {
    /* read from stdin, commands/data to be dealt with and possibly passed on
       to the socket

       protocol:

       4 letter command + LF [mandatory]

       4-digit hexadecimal data length + LF [if the command takes data]
       data                       [the data being as long as set above]

       Commands:

       DATA - plain pass-thru data
    */

    if(!read_stdin(buffer, 5))
      return FALSE;

    logmsg("Received %c%c%c%c (on stdin)",
           buffer[0], buffer[1], buffer[2], buffer[3] );

    if(!memcmp("PING", buffer, 4)) {
      /* send reply on stdout, just proving we are alive */
      if(!write_stdout("PONG\n", 5))
        return FALSE;
    }

    else if(!memcmp("PORT", buffer, 4)) {
      /* Question asking us what PORT number we are listening to.
         Replies to PORT with "IPv[num]/[port]" */
      sprintf((char *)buffer, "%s/%hu\n", ipv_inuse, port);
      buffer_len = (ssize_t)strlen((char *)buffer);
      snprintf(data, sizeof(data), "PORT\n%04zx\n", buffer_len);
      if(!write_stdout(data, 10))
        return FALSE;
      if(!write_stdout(buffer, buffer_len))
        return FALSE;
    }
    else if(!memcmp("QUIT", buffer, 4)) {
      /* just die */
      logmsg("quits");
      return FALSE;
    }
    else if(!memcmp("DATA", buffer, 4)) {
      /* data IN => data OUT */

      if(!read_stdin(buffer, 5))
        return FALSE;

      buffer[5] = '\0';

      buffer_len = (ssize_t)strtol((char *)buffer, NULL, 16);
      if (buffer_len > (ssize_t)sizeof(buffer)) {
        logmsg("ERROR: Buffer size (%zu bytes) too small for data size "
               "(%zd bytes)", sizeof(buffer), buffer_len);
        return FALSE;
      }
      logmsg("> %zd bytes data, server => client", buffer_len);

      if(!read_stdin(buffer, buffer_len))
        return FALSE;

      lograw(buffer, buffer_len);

      if(*mode == PASSIVE_LISTEN) {
        logmsg("*** We are disconnected!");
        if(!write_stdout("DISC\n", 5))
          return FALSE;
      }
      else {
        /* send away on the socket */
        bytes_written = swrite(sockfd, buffer, buffer_len);
        if(bytes_written != buffer_len) {
          logmsg("Not all data was sent. Bytes to send: %zd sent: %zd",
                 buffer_len, bytes_written);
        }
      }
    }
    else if(!memcmp("DISC", buffer, 4)) {
      /* disconnect! */
      if(!write_stdout("DISC\n", 5))
        return FALSE;
      if(sockfd != CURL_SOCKET_BAD) {
        logmsg("====> Client forcibly disconnected");
        sclose(sockfd);
        *sockfdp = CURL_SOCKET_BAD;
        if(*mode == PASSIVE_CONNECT)
          *mode = PASSIVE_LISTEN;
        else
          *mode = ACTIVE_DISCONNECT;
      }
      else
        logmsg("attempt to close already dead connection");
      return TRUE;
    }
  }


  if((sockfd != CURL_SOCKET_BAD) && (FD_ISSET(sockfd, &fds_read)) ) {

    if(*mode == PASSIVE_LISTEN) {
      /* there's no stream set up yet, this is an indication that there's a
         client connecting. */
      sockfd = accept(sockfd, NULL, NULL);
      if(CURL_SOCKET_BAD == sockfd)
        logmsg("accept() failed");
      else {
        logmsg("====> Client connect");
        if(!write_stdout("CNCT\n", 5))
          return FALSE;
        *sockfdp = sockfd; /* store the new socket */
        *mode = PASSIVE_CONNECT; /* we have connected */
      }
      return TRUE;
    }

    /* read from socket, pass on data to stdout */
    nread_socket = sread(sockfd, buffer, sizeof(buffer));

    if(nread_socket <= 0) {
      logmsg("====> Client disconnect");
      if(!write_stdout("DISC\n", 5))
        return FALSE;
      sclose(sockfd);
      *sockfdp = CURL_SOCKET_BAD;
      if(*mode == PASSIVE_CONNECT)
        *mode = PASSIVE_LISTEN;
      else
        *mode = ACTIVE_DISCONNECT;
      return TRUE;
    }

    snprintf(data, sizeof(data), "DATA\n%04zx\n", nread_socket);
    if(!write_stdout(data, 10))
      return FALSE;
    if(!write_stdout(buffer, nread_socket))
      return FALSE;

    logmsg("< %zd bytes data, client => server", nread_socket);
    lograw(buffer, nread_socket);
  }

  return TRUE;
}

static curl_socket_t sockdaemon(curl_socket_t sock,
                                unsigned short *listenport)
{
  /* passive daemon style */
  struct sockaddr_in me;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 me6;
#endif /* ENABLE_IPV6 */
  int flag;
  int rc;
  int totdelay = 0;
  int maxretr = 10;
  int delay= 20;
  int attempt = 0;
  int error = 0;

  do {
    attempt++;
    flag = 1;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
         (void *)&flag, sizeof(flag));
    if(rc) {
      error = SOCKERRNO;
      logmsg("setsockopt(SO_REUSEADDR) failed with error: (%d) %s",
             error, strerror(error));
      if(maxretr) {
        rc = wait_ms(delay);
        if(rc) {
          /* should not happen */
          error = SOCKERRNO;
          logmsg("wait_ms() failed with error: (%d) %s",
                 error, strerror(error));
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        if(got_exit_signal) {
          logmsg("signalled to die, exiting...");
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        totdelay += delay;
        delay *= 2; /* double the sleep for next attempt */
      }
    }
  } while(rc && maxretr--);

  if(rc) {
    logmsg("setsockopt(SO_REUSEADDR) failed %d times in %d ms. Error: (%d) %s",
           attempt, totdelay, error, strerror(error));
    logmsg("Continuing anyway...");
  }

  /* When the specified listener port is zero, it is actually a
     request to let the system choose a non-zero available port. */

#ifdef ENABLE_IPV6
  if(!use_ipv6) {
#endif
    memset(&me, 0, sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(*listenport);
    rc = bind(sock, (struct sockaddr *) &me, sizeof(me));
#ifdef ENABLE_IPV6
  }
  else {
    memset(&me6, 0, sizeof(me6));
    me6.sin6_family = AF_INET6;
    me6.sin6_addr = in6addr_any;
    me6.sin6_port = htons(*listenport);
    rc = bind(sock, (struct sockaddr *) &me6, sizeof(me6));
  }
#endif /* ENABLE_IPV6 */
  if(rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu: (%d) %s",
           *listenport, error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  if(!*listenport) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    struct sockaddr *localaddr;
    struct sockaddr_in localaddr4;
#ifdef ENABLE_IPV6
    struct sockaddr_in6 localaddr6;
    if(!use_ipv6) {
#endif
      la_size = sizeof(localaddr4);
      localaddr = (struct sockaddr *)&localaddr4;
#ifdef ENABLE_IPV6
    }
    else {
      la_size = sizeof(localaddr6);
      localaddr = (struct sockaddr *)&localaddr6;
    }
#endif
    memset(localaddr, 0, (size_t)la_size);
    if(getsockname(sock, localaddr, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error: (%d) %s",
             error, strerror(error));
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
    switch (localaddr->sa_family) {
    case AF_INET:
      *listenport = ntohs(localaddr4.sin_port);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      *listenport = ntohs(localaddr6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!*listenport) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
  }

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen() failed with error: (%d) %s",
           error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  return sock;
}


int main(int argc, char *argv[])
{
  struct sockaddr_in me;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 me6;
#endif /* ENABLE_IPV6 */
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  char *pidname= (char *)".sockfilt.pid";
  bool juggle_again;
  int rc;
  int error;
  int arg=1;
  enum sockmode mode = PASSIVE_LISTEN; /* default */
  const char *addr = NULL;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("sockfilt IPv4%s\n",
#ifdef ENABLE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--verbose", argv[arg])) {
      verbose = TRUE;
      arg++;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc>arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef ENABLE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
#ifdef ENABLE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        if((endptr != argv[arg] + strlen(argv[arg])) ||
           ((ulnum != 0UL) && ((ulnum < 1025UL) || (ulnum > 65535UL)))) {
          fprintf(stderr, "sockfilt: invalid --port argument (%s)\n",
                  argv[arg]);
          return 0;
        }
        port = curlx_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--connect", argv[arg])) {
      /* Asked to actively connect to the specified local port instead of
         doing a passive server-style listening. */
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        if((endptr != argv[arg] + strlen(argv[arg])) ||
           (ulnum < 1025UL) || (ulnum > 65535UL)) {
          fprintf(stderr, "sockfilt: invalid --connect argument (%s)\n",
                  argv[arg]);
          return 0;
        }
        connectport = curlx_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--addr", argv[arg])) {
      /* Set an IP address to use with --connect; otherwise use localhost */
      arg++;
      if(argc>arg) {
        addr = argv[arg];
        arg++;
      }
    }
    else {
      puts("Usage: sockfilt [option]\n"
           " --version\n"
           " --verbose\n"
           " --logfile [file]\n"
           " --pidfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --port [port]\n"
           " --connect [port]\n"
           " --addr [address]");
      return 0;
    }
  }

#ifdef WIN32
  win32_init();
  atexit(win32_cleanup);
#endif

  install_signal_handlers();

#ifdef ENABLE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef ENABLE_IPV6
  else
    sock = socket(AF_INET6, SOCK_STREAM, 0);
#endif

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket: (%d) %s",
           error, strerror(error));
    goto sockfilt_cleanup;
  }

  if(connectport) {
    /* Active mode, we should connect to the given port number */
    mode = ACTIVE;
#ifdef ENABLE_IPV6
    if(!use_ipv6) {
#endif
      memset(&me, 0, sizeof(me));
      me.sin_family = AF_INET;
      me.sin_port = htons(connectport);
      me.sin_addr.s_addr = INADDR_ANY;
      if (!addr)
        addr = "127.0.0.1";
      Curl_inet_pton(AF_INET, addr, &me.sin_addr);

      rc = connect(sock, (struct sockaddr *) &me, sizeof(me));
#ifdef ENABLE_IPV6
    }
    else {
      memset(&me6, 0, sizeof(me6));
      me6.sin6_family = AF_INET6;
      me6.sin6_port = htons(connectport);
      if (!addr)
        addr = "::1";
      Curl_inet_pton(AF_INET6, addr, &me6.sin6_addr);

      rc = connect(sock, (struct sockaddr *) &me6, sizeof(me6));
    }
#endif /* ENABLE_IPV6 */
    if(rc) {
      error = SOCKERRNO;
      logmsg("Error connecting to port %hu: (%d) %s",
             connectport, error, strerror(error));
      goto sockfilt_cleanup;
    }
    logmsg("====> Client connect");
    msgsock = sock; /* use this as stream */
  }
  else {
    /* passive daemon style */
    sock = sockdaemon(sock, &port);
    if(CURL_SOCKET_BAD == sock)
      goto sockfilt_cleanup;
    msgsock = CURL_SOCKET_BAD; /* no stream socket yet */
  }

  logmsg("Running %s version", ipv_inuse);

  if(connectport)
    logmsg("Connected to port %hu", connectport);
  else
    logmsg("Listening on port %hu", port);

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile)
    goto sockfilt_cleanup;

  do {
    juggle_again = juggle(&msgsock, sock, &mode);
  } while(juggle_again);

sockfilt_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(wrotepidfile)
    unlink(pidname);

  restore_signal_handlers();

  if(got_exit_signal) {
    logmsg("============> sockfilt exits with signal (%d)", exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("============> sockfilt quits");
  return 0;
}

