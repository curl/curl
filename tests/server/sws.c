/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

/* sws.c: simple (silly?) web server

   This code was originally graciously donated to the project by Juergen
   Wilke. Thanks a bunch!

 */
#include "setup.h" /* portability help from the lib directory */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HPUX 11 */
#include <arpa/inet.h> 
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "getpart.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#if defined(WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <winsock2.h>
#include <process.h>

#define sleep(sec)   Sleep ((sec)*1000)
#ifdef _MSC_VER
#define strncasecmp  strnicmp
#endif

#define EINPROGRESS  WSAEINPROGRESS
#define EWOULDBLOCK  WSAEWOULDBLOCK
#define EISCONN      WSAEISCONN
#define ENOTSOCK     WSAENOTSOCK
#define ECONNREFUSED WSAECONNREFUSED

static void win32_cleanup(void);
#endif

#define REQBUFSIZ 150000
#define REQBUFSIZ_TXT "149999"

long prevtestno=-1; /* previous test number we served */
long prevpartno=-1; /* previous part number we served */
bool prevbounce;    /* instructs the server to increase the part number for
                       a test in case the identical testno+partno request
                       shows up again */

struct httprequest {
  char reqbuf[REQBUFSIZ]; /* buffer area for the incoming request */
  int offset;     /* size of the incoming request */
  long testno;     /* test number found in the request */
  long partno;     /* part number found in the request */
  int open;       /* keep connection open info, as found in the request */
  bool auth_req;  /* authentication required, don't wait for body unless
                     there's an Authorization header */
  bool auth;      /* Authorization header present in the incoming request */
  size_t cl;      /* Content-Length of the incoming request */
  bool digest;    /* Authorization digest header found */
  bool ntlm;      /* Authorization ntlm header found */
};

int ProcessRequest(struct httprequest *req);
void storerequest(char *reqbuf);

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sws.log"
#endif

#define SWSVERSION "cURL test suite HTTP server/0.1"

#define REQUEST_DUMP  "log/server.input"
#define RESPONSE_DUMP "log/server.response"

#define TEST_DATA_PATH "%s/data/test%d"

/* very-big-path support */
#define MAXDOCNAMELEN 140000
#define MAXDOCNAMELEN_TXT "139999"

#define REQUEST_KEYWORD_SIZE 256

#define CMD_AUTH_REQUIRED "auth_required"

#define END_OF_HEADERS "\r\n\r\n"

/* global variable, where to find the 'data' dir */
const char *path=".";

enum {
  DOCNUMBER_NOTHING = -7,
  DOCNUMBER_QUIT    = -6,
  DOCNUMBER_BADCONNECT = -5,
  DOCNUMBER_INTERNAL= -4,
  DOCNUMBER_CONNECT = -3,
  DOCNUMBER_WERULEZ = -2,
  DOCNUMBER_404     = -1
};


/* sent as reply to a QUIT */
static const char *docquit =
"HTTP/1.1 200 Goodbye" END_OF_HEADERS;

/* sent as reply to a CONNECT */
static const char *docconnect =
"HTTP/1.1 200 Mighty fine indeed" END_OF_HEADERS;

/* sent as reply to a "bad" CONNECT */
static const char *docbadconnect =
"HTTP/1.1 501 Forbidden you fool" END_OF_HEADERS;

/* send back this on 404 file not found */
static const char *doc404 = "HTTP/1.1 404 Not Found\r\n"
    "Server: " SWSVERSION "\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html"
    END_OF_HEADERS
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<HTML><HEAD>\n"
    "<TITLE>404 Not Found</TITLE>\n"
    "</HEAD><BODY>\n"
    "<H1>Not Found</H1>\n"
    "The requested URL was not found on this server.\n"
    "<P><HR><ADDRESS>" SWSVERSION "</ADDRESS>\n" "</BODY></HTML>\n";

#ifdef SIGPIPE
static volatile int sigpipe;  /* Why? It's not used */
#endif

static void logmsg(const char *msg, ...)
{
  time_t t = time(NULL);
  va_list ap;
  struct tm *curr_time = localtime(&t);
  char buffer[256]; /* possible overflow if you pass in a huge string */
  FILE *logfp;
   
  va_start(ap, msg);
  vsprintf(buffer, msg, ap);
  va_end(ap);

  logfp = fopen(DEFAULT_LOGFILE, "a");

  fprintf(logfp?logfp:stderr, /* write to stderr if the logfile doesn't open */
          "%02d:%02d:%02d (%d) %s\n",
          curr_time->tm_hour,
          curr_time->tm_min,
          curr_time->tm_sec, (int)getpid(), buffer);
  if(logfp)
    fclose(logfp);
}


#ifdef SIGPIPE
static void sigpipe_handler(int sig)
{
  (void)sig; /* prevent warning */
  sigpipe = 1;
}
#endif

#if defined(WIN32) && !defined(__CYGWIN__)
#undef perror
#define perror(m) win32_perror(m)

static void win32_perror (const char *msg)
{
  char buf[256];
  DWORD err = WSAGetLastError();

  if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                     LANG_NEUTRAL, buf, sizeof(buf), NULL))
     snprintf(buf, sizeof(buf), "Unknown error %lu (%#lx)", err, err);
  if (msg)
     fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}
#endif

static char *test2file(int testno)
{
  static char filename[256];
  sprintf(filename, TEST_DATA_PATH, path, testno);
  return filename;
}


int ProcessRequest(struct httprequest *req)
{
  char *line=req->reqbuf;
  char chunked=FALSE;
  static char request[REQUEST_KEYWORD_SIZE];
  static char doc[MAXDOCNAMELEN];
  char logbuf[256];
  int prot_major, prot_minor;
  char *end;
  end = strstr(req->reqbuf, END_OF_HEADERS);

  /* try to figure out the request characteristics as soon as possible, but
     only once! */
  if((req->testno == DOCNUMBER_NOTHING) &&
     sscanf(line, "%" REQBUFSIZ_TXT"s %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
            request,
            doc,
            &prot_major,
            &prot_minor) == 4) {
    char *ptr;

    /* find the last slash */
    ptr = strrchr(doc, '/');

    /* get the number after it */
    if(ptr) {
      FILE *stream;
      char *filename;

      if((strlen(doc) + strlen(request)) < 200)
        sprintf(logbuf, "Got request: %s %s HTTP/%d.%d",
                request, doc, prot_major, prot_minor);
      else
        sprintf(logbuf, "Got a *HUGE* request HTTP/%d.%d",
                prot_major, prot_minor);
      logmsg(logbuf);
      
      if(!strncmp("/verifiedserver", ptr, 15)) {
        logmsg("Are-we-friendly question received");
        req->testno = DOCNUMBER_WERULEZ;
        return 1; /* done */
      }

      if(!strncmp("/quit", ptr, 15)) {
        logmsg("Request-to-quit received");
        req->testno = DOCNUMBER_QUIT;
        return 1; /* done */
      }

      ptr++; /* skip the slash */

      req->testno = strtol(ptr, &ptr, 10);

      if(req->testno > 10000) {
        req->partno = req->testno % 10000;
        req->testno /= 10000;
      }
      else
        req->partno = 0;

      sprintf(logbuf, "Requested test number %ld part %ld",
              req->testno, req->partno);

      logmsg(logbuf);

      filename = test2file(req->testno);

      stream=fopen(filename, "rb");
      if(!stream) {
        logmsg("Couldn't open test file %d", req->testno);
        return 0;
      }
      else {    
        char *cmd = NULL;
        size_t cmdsize = 0;

        /* get the custom server control "commands" */
        cmd = (char *)spitout(stream, "reply", "servercmd", &cmdsize);
        fclose(stream);

        if(cmdsize) {
          logmsg("Found a reply-servercmd section!");

          if(!strncmp(CMD_AUTH_REQUIRED, cmd, strlen(CMD_AUTH_REQUIRED))) {
            logmsg("instructed to require authorization header");
            req->auth_req = TRUE;
          }
          free(cmd);
        }
      }
    }
    else {
      if(sscanf(req->reqbuf, "CONNECT %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
                doc, &prot_major, &prot_minor) == 3) {
        sprintf(logbuf, "Receiced a CONNECT %s HTTP/%d.%d request", 
                doc, prot_major, prot_minor);
        logmsg(logbuf);

        if(prot_major*10+prot_minor == 10)
          req->open = FALSE; /* HTTP 1.0 closes connection by default */

        if(!strncmp(doc, "bad", 3))
          /* if the host name starts with bad, we fake an error here */
          req->testno = DOCNUMBER_BADCONNECT;
        else if(!strncmp(doc, "test", 4)) {
          char *ptr = strchr(doc, ':');
          if(ptr)
            req->testno = atoi(ptr+1);
          else
            req->testno = DOCNUMBER_CONNECT;
        }
        else
          req->testno = DOCNUMBER_CONNECT;
      }
      else {
        logmsg("Did not find test number in PATH");
        req->testno = DOCNUMBER_404;
      }
    }
  }

  if(!end)
    /* we don't have a complete request yet! */
    return 0;

  /* **** Persistancy ****
   *
   * If the request is a HTTP/1.0 one, we close the connection unconditionally
   * when we're done.
   *
   * If the request is a HTTP/1.1 one, we MUST check for a "Connection:"
   * header that might say "close". If it does, we close a connection when
   * this request is processed. Otherwise, we keep the connection alive for X
   * seconds.
   */

  do {
    if(!req->cl && !strncasecmp("Content-Length:", line, 15)) {
      /* If we don't ignore content-length, we read it and we read the whole
         request including the body before we return. If we've been told to
         ignore the content-length, we will return as soon as all headers
         have been received */
      req->cl = strtol(line+15, &line, 10);

      logmsg("Found Content-Legth: %d in the request", req->cl);
      break;
    }
    else if(!strncasecmp("Transfer-Encoding: chunked", line,
                         strlen("Transfer-Encoding: chunked"))) {
      /* chunked data coming in */
      chunked = TRUE;
    }

    if(chunked) {
      if(strstr(req->reqbuf, "\r\n0\r\n"))
        /* end of chunks reached */
        return 1; /* done */
      else
        return 0; /* not done */
    }

    line = strchr(line, '\n');
    if(line)
      line++;
  } while(line);

  if(!req->auth && strstr(req->reqbuf, "Authorization:")) {
    req->auth = TRUE; /* Authorization: header present! */
    if(req->auth_req)
      logmsg("Authorization header found, as required");
  }

  if(!req->digest && strstr(req->reqbuf, "Authorization: Digest")) {
    /* If the client is passing this Digest-header, we set the part number
       to 1000. Not only to spice up the complexity of this, but to make
       Digest stuff to work in the test suite. */
    req->partno += 1000;
    req->digest = TRUE; /* header found */
    logmsg("Received Digest request, sending back data %d", req->partno);
  }
  else if(!req->ntlm &&
          strstr(req->reqbuf, "Authorization: NTLM TlRMTVNTUAAD")) {
    /* If the client is passing this type-3 NTLM header */
    req->partno += 1002;
    req->ntlm = TRUE; /* NTLM found */
    logmsg("Received NTLM type-3, sending back data %d", req->partno);
  }
  else if(!req->ntlm &&
          strstr(req->reqbuf, "Authorization: NTLM TlRMTVNTUAAB")) {
    /* If the client is passing this type-1 NTLM header */
    req->partno += 1001;
    req->ntlm = TRUE; /* NTLM found */
    logmsg("Received NTLM type-1, sending back data %d", req->partno);
  }
  if(strstr(req->reqbuf, "Connection: close"))
    req->open = FALSE; /* close connection after this request */

  if(req->cl && (req->auth || !req->auth_req)) {
    if(req->cl <= strlen(end+strlen(END_OF_HEADERS)))
      return 1; /* done */
    else
      return 0; /* not complete yet */
  }
  return 1; /* done */
}

/* store the entire request in a file */
void storerequest(char *reqbuf)
{
  FILE *dump;

  dump = fopen(REQUEST_DUMP, "ab"); /* b is for windows-preparing */
  if(dump) {
    fwrite(reqbuf, 1, strlen(reqbuf), dump);

    fclose(dump);
    logmsg("Wrote request input to " REQUEST_DUMP);
  }
  else {
    logmsg("Failed to write request input to " REQUEST_DUMP);
  }
}

/* return 0 on success, non-zero on failure */
static int get_request(int sock, struct httprequest *req)
{
  int fail= FALSE;
  char *reqbuf = req->reqbuf;

  /*** Init the httpreqest structure properly for the upcoming request ***/
  memset(req, 0, sizeof(struct httprequest));

  /* here's what should not be 0 from the start */
  req->testno = DOCNUMBER_NOTHING; /* safe default */
  req->open = TRUE; /* connection should remain open and wait for more
                       commands */

  /*** end of httprequest init ***/

  while (req->offset < REQBUFSIZ) {
    int got = sread(sock, reqbuf + req->offset, REQBUFSIZ - req->offset);
    if (got <= 0) {
      if (got < 0) {
        perror("recv");
        logmsg("recv() returned error");
        return DOCNUMBER_INTERNAL;
      }
      logmsg("Connection closed by client");
      return DOCNUMBER_INTERNAL;
    }
    req->offset += got;

    reqbuf[req->offset] = 0;

    if(ProcessRequest(req))
      break;
  }

  if (req->offset >= REQBUFSIZ) {
    logmsg("Request buffer overflow, closing connection");
    reqbuf[REQBUFSIZ-1]=0;
    fail = TRUE;
    /* dump the request to an external file anyway */
  }
  else
    reqbuf[req->offset]=0;
  
  /* dump the request to an external file */
  storerequest(reqbuf);

  return fail; /* success */
}

/* returns -1 on failure */
static int send_doc(int sock, struct httprequest *req)
{
  int written;
  size_t count;
  const char *buffer;
  char *ptr;
  FILE *stream;
  char *cmd=NULL;
  size_t cmdsize=0;
  FILE *dump;
  int persistant = TRUE;
  size_t responsesize;

  static char weare[256];

  char partbuf[80]="data";

  req->open = FALSE;

  logmsg("Send response number %d part %d", req->testno, req->partno);

  if(req->testno < 0) {
    switch(req->testno) {
    case DOCNUMBER_QUIT:
      logmsg("Replying to QUIT");
      buffer = docquit;
      break;
    case DOCNUMBER_WERULEZ:
      /* we got a "friends?" question, reply back that we sure are */
      logmsg("Identifying ourselves as friends");
      sprintf(weare, "HTTP/1.1 200 OK\r\n\r\nWE ROOLZ: %d\r\n",
              (int)getpid());
      buffer = weare;
      break;
    case DOCNUMBER_INTERNAL:
      logmsg("Bailing out due to internal error");
      return -1;
    case DOCNUMBER_CONNECT:
      logmsg("Replying to CONNECT");
      buffer = docconnect;
      break;
    case DOCNUMBER_BADCONNECT:
      logmsg("Replying to a bad CONNECT");
      buffer = docbadconnect;
      break;
    case DOCNUMBER_404:
    default:
      logmsg("Replying to with a 404");
      buffer = doc404;
      break;
    }
    ptr = NULL;
    stream=NULL;

    count = strlen(buffer);
  }
  else {
    char *filename = test2file(req->testno);

    if(0 != req->partno)
      sprintf(partbuf, "data%ld", req->partno);

    stream=fopen(filename, "rb");
    if(!stream) {
      logmsg("Couldn't open test file");
      return 0;
    }
    else {
      buffer = spitout(stream, "reply", partbuf, &count);
      ptr = (char *)buffer;
      fclose(stream);
    }

    /* re-open the same file again */
    stream=fopen(filename, "rb");
    if(!stream) {
      logmsg("Couldn't open test file");
      return 0;
    }
    else {    
      /* get the custom server control "commands" */
      cmd = (char *)spitout(stream, "reply", "postcmd", &cmdsize);
      fclose(stream);
    }
  }

  dump = fopen(RESPONSE_DUMP, "ab"); /* b is for windows-preparing */
  if(!dump) {
    logmsg("couldn't create logfile: " RESPONSE_DUMP);
    return -1;
  }

  /* If the word 'swsclose' is present anywhere in the reply chunk, the
     connection will be closed after the data has been sent to the requesting
     client... */
  if(strstr(buffer, "swsclose") || !count) {
    persistant = FALSE;
    logmsg("connection close instruction \"swsclose\" found in response");
  }
  if(strstr(buffer, "swsbounce")) {
    prevbounce = TRUE;
    logmsg("enable \"swsbounce\" in the next request");
  }
  else
    prevbounce = FALSE;


  responsesize = count;
  do {
    written = swrite(sock, buffer, count);
    if (written < 0) {
      logmsg("Sending response failed and we bailed out!");
      return -1;
    }
    /* write to file as well */
    fwrite(buffer, 1, written, dump);

    count -= written;
    buffer += written;
  } while(count>0);

  fclose(dump);

  logmsg("Response sent (%d bytes)!", responsesize);

  if(ptr)
    free(ptr);

  if(cmdsize > 0 ) {
    char command[32];
    int num;
    char *ptr=cmd;
    do {
      if(2 == sscanf(ptr, "%31s %d", command, &num)) {
        if(!strcmp("wait", command)) {
          logmsg("Told to sleep for %d seconds", num);
          sleep(num); /* wait this many seconds */
        }
        else
          logmsg("Unknown command in reply command section");
      }
      ptr = strchr(ptr, '\n');
      if(ptr)
        ptr++;
      else
        ptr = NULL;
    } while(ptr && *ptr);
  }
  if(cmd)
    free(cmd);

  req->open = persistant;

  prevtestno = req->testno;
  prevpartno = req->partno;

  return 0;
}

#if defined(WIN32) && !defined(__CYGWIN__)
static void win32_init(void)
{
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(2, 0); 
    
  err = WSAStartup(wVersionRequested, &wsaData); 
    
  if (err != 0) {
    perror("Winsock init failed");
    logmsg("Error initialising winsock -- aborting\n");
    exit(1);
  }
    
  if ( LOBYTE( wsaData.wVersion ) != 2 || 
       HIBYTE( wsaData.wVersion ) != 0 ) { 
 
    WSACleanup(); 
    perror("Winsock init failed");
    logmsg("No suitable winsock.dll found -- aborting\n");
    exit(1);
  }
}
static void win32_cleanup(void)
{
  WSACleanup();
}
#endif

int main(int argc, char *argv[])
{
  struct sockaddr_in me;
  int sock, msgsock, flag;
  unsigned short port = DEFAULT_PORT;
  FILE *pidfile;
  struct httprequest req;
  
  if(argc>1) {
    port = (unsigned short)atoi(argv[1]);

    if(argc>2) {
      path = argv[2];
    }
  }
  
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
  win32_init();
  atexit(win32_cleanup);
#else

#ifdef SIGPIPE
#ifdef HAVE_SIGNAL
  signal(SIGPIPE, sigpipe_handler);
#endif
#ifdef HAVE_SIGINTERRUPT
  siginterrupt(SIGPIPE, 1);
#endif
#endif
#endif

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("opening stream socket");
    logmsg("Error opening socket -- aborting\n");
    exit(1);
  }

  flag = 1;
  if (setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &flag,
       sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR)");
  }

  me.sin_family = AF_INET;
  me.sin_addr.s_addr = INADDR_ANY;
  me.sin_port = htons(port);
  if (bind(sock, (struct sockaddr *) &me, sizeof me) < 0) {
    perror("binding stream socket");
    logmsg("Error binding socket -- aborting\n");
    exit(1);
  }

  pidfile = fopen(".http.pid", "w");
  if(pidfile) {
    fprintf(pidfile, "%d\n", (int)getpid());
    fclose(pidfile);
  }
  else
    fprintf(stderr, "Couldn't write pid file\n");

  /* start accepting connections */
  listen(sock, 5);

  while (1) {
    msgsock = accept(sock, NULL, NULL);
    
    if (msgsock == -1)
      continue;
    
    logmsg("** New client connected");

    do {
      if(get_request(msgsock, &req))
        /* non-zero means error, break out of loop */
        break;

      if(prevbounce) {
        /* bounce treatment requested */
        if((req.testno == prevtestno) &&
           (req.partno == prevpartno)) {
          req.partno++;
          logmsg("BOUNCE part number to %ld", req.partno);
        }
      }

      send_doc(msgsock, &req);

      if((req.testno < 0) && (req.testno != DOCNUMBER_CONNECT)) {
        logmsg("special request received, no persistancy");
        break;
      }
      if(!req.open) {
        logmsg("instructed to close connection after server-reply");
        break;
      }

      if(req.open)
        logmsg("persistant connection, awaits new request");
      /* if we got a CONNECT, loop and get another request as well! */
    } while(req.open || (req.testno == DOCNUMBER_CONNECT));

    logmsg("** Closing client connection");
    sclose(msgsock);

    if (req.testno == DOCNUMBER_QUIT)
      break;
  }
  
  sclose(sock);
  
  return 0;
}

