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
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HPUX 11 */
#include <arpa/inet.h> 
#endif
#include <netdb.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

const char *
spitout(FILE *stream,
        const char *main,
        const char *sub, int *size);

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sws.log"
#endif

#define SWSVERSION "cURL test suite HTTP server/0.1"

#define REQUEST_DUMP  "log/server.input"
#define RESPONSE_DUMP "log/server.response"

#define TEST_DATA_PATH "%s/data/test%d"

/* global variable, where to find the 'data' dir */
char *path=".";

enum {
  DOCNUMBER_QUIT    = -6,
  DOCNUMBER_BADCONNECT = -5,
  DOCNUMBER_INTERNAL= -4,
  DOCNUMBER_CONNECT = -3,
  DOCNUMBER_WERULEZ = -2,
  DOCNUMBER_404     = -1
};


/* sent as reply to a QUIT */
static const char *docquit =
"HTTP/1.1 200 Goodbye\r\n"
"\r\n";

/* sent as reply to a CONNECT */
static const char *docconnect =
"HTTP/1.1 200 Mighty fine indeed\r\n"
"\r\n";

/* sent as reply to a "bad" CONNECT */
static const char *docbadconnect =
"HTTP/1.1 501 Forbidden you fool\r\n"
"\r\n";

/* send back this on 404 file not found */
static const char *doc404 = "HTTP/1.1 404 Not Found\n"
    "Server: " SWSVERSION "\n"
    "Connection: close\n"
    "Content-Type: text/html\n"
    "\n"
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<HTML><HEAD>\n"
    "<TITLE>404 Not Found</TITLE>\n"
    "</HEAD><BODY>\n"
    "<H1>Not Found</H1>\n"
    "The requested URL was not found on this server.\n"
    "<P><HR><ADDRESS>" SWSVERSION "</ADDRESS>\n" "</BODY></HTML>\n";

#ifdef HAVE_SIGNAL
static volatile int sigpipe;
#endif
static FILE *logfp;


static void logmsg(const char *msg, ...)
{
  time_t t = time(NULL);
  va_list ap;
  struct tm *curr_time = localtime(&t);
  char loctime[80];
  char buffer[256]; /* possible overflow if you pass in a huge string */
   
  va_start(ap, msg);
  vsprintf(buffer, msg, ap);
  va_end(ap);

  strcpy(loctime, asctime(curr_time));
  loctime[strlen(loctime) - 1] = '\0';
  fprintf(logfp, "%s: %d: %s\n", loctime, (int)getpid(), buffer);
  fflush(logfp);
}


#ifdef HAVE_SIGNAL
static void sigpipe_handler(int sig)
{
  (void)sig; /* prevent warning */
  sigpipe = 1;
}
#endif

int ProcessRequest(char *request)
{
  char *line=request;
  unsigned long contentlength=0;
  char chunked=FALSE;

#define END_OF_HEADERS "\r\n\r\n"

  char *end;
  end = strstr(request, END_OF_HEADERS);

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
    if(!strncasecmp("Content-Length:", line, 15)) {
      contentlength = strtol(line+15, &line, 10);
      break;
    }
    else if(!strncasecmp("Transfer-Encoding: chunked", line,
                         strlen("Transfer-Encoding: chunked"))) {
      /* chunked data coming in */
      chunked = TRUE;
    }

    if(chunked) {
      if(strstr(request, "\r\n0\r\n"))
        /* end of chunks reached */
        return 1; /* done */
      else
        return 0; /* not done */
    }

    line = strchr(line, '\n');
    if(line)
      line++;
  } while(line);

  if(contentlength > 0 ) {
    if(contentlength <= strlen(end+strlen(END_OF_HEADERS)))
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


#define REQBUFSIZ 150000
#define REQBUFSIZ_TXT "149999"

/* very-big-path support */
#define MAXDOCNAMELEN 140000
#define MAXDOCNAMELEN_TXT "139999"

#define REQUEST_KEYWORD_SIZE 256
static int get_request(int sock, int *part, int *open)
{
  static char reqbuf[REQBUFSIZ], doc[MAXDOCNAMELEN];
  static char request[REQUEST_KEYWORD_SIZE];
  unsigned int offset = 0;
  int prot_major, prot_minor;
  char logbuf[256];

  *part = 0; /* part zero equals none */

  *open = TRUE; /* connection should remain open and wait for more commands */

  while (offset < REQBUFSIZ) {
    int got = sread(sock, reqbuf + offset, REQBUFSIZ - offset);
    if (got <= 0) {
      if (got < 0) {
        perror("recv");
        logmsg("recv() returned error");
        return DOCNUMBER_INTERNAL;
      }
      logmsg("Connection closed by client");
      return DOCNUMBER_INTERNAL;
    }
    offset += got;

    reqbuf[offset] = 0;

    if(ProcessRequest(reqbuf))
      break;
  }

  if (offset >= REQBUFSIZ) {
    logmsg("Request buffer overflow, closing connection");
    /* dump the request to an external file anyway */
    reqbuf[REQBUFSIZ-1]=0;
    storerequest(reqbuf);

    return DOCNUMBER_INTERNAL;
  }
  reqbuf[offset]=0;
  
  /* dump the request to an external file */
  storerequest(reqbuf);

  if(sscanf(reqbuf, "%" REQBUFSIZ_TXT"s %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
            request,
            doc,
            &prot_major,
            &prot_minor) == 4) {
    char *ptr;
    int test_no=0;

    /* find the last slash */
    ptr = strrchr(doc, '/');

    /* get the number after it */
    if(ptr) {

      if((strlen(doc) + strlen(request)) < 200)
        sprintf(logbuf, "Got request: %s %s HTTP/%d.%d",
                request, doc, prot_major, prot_minor);
      else
        sprintf(logbuf, "Got a *HUGE* request HTTP/%d.%d",
                prot_major, prot_minor);
      logmsg(logbuf);
      
      if(!strncmp("/verifiedserver", ptr, 15)) {
        logmsg("Are-we-friendly question received");
        return DOCNUMBER_WERULEZ;
      }

      if(!strncmp("/quit", ptr, 15)) {
        logmsg("Request-to-quit received");
        return DOCNUMBER_QUIT;
      }

      ptr++; /* skip the slash */

      test_no = strtol(ptr, &ptr, 10);

      if(test_no > 10000) {
        *part = test_no % 10000;
        test_no /= 10000;
      }
      else
        *part = 0;

      sprintf(logbuf, "Found test number %d in path", test_no);
      logmsg(logbuf);

      if(strstr(reqbuf, "Authorization: Digest")) {
        /* If the client is passing this Digest-header, we set the part number
           to 1000. Not only to spice up the complexity of this, but to make
           Digest stuff to work in the test suite. */
        *part += 1000;
        logmsg("Received Digest request, sending back data %d", *part);
      }
      else if(strstr(reqbuf, "Authorization: NTLM TlRMTVNTUAAD")) {
        /* If the client is passing this type-3 NTLM header */
        *part += 1002;
        logmsg("Received NTLM type-3, sending back data %d", *part);
      }
      else if(strstr(reqbuf, "Authorization: NTLM TlRMTVNTUAAB")) {
        /* If the client is passing this type-1 NTLM header */
        *part += 1001;
        logmsg("Received NTLM type-1, sending back data %d", *part);
      }

      if(strstr(reqbuf, "Connection: close"))
        *open = FALSE; /* close connection after this request */
    }
    else {
      if(sscanf(reqbuf, "CONNECT %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
                doc,
                &prot_major, &prot_minor) == 3) {
        sprintf(logbuf, "Receiced a CONNECT %s HTTP/%d.%d request", 
                doc, prot_major, prot_minor);
        logmsg(logbuf);

        if(prot_major*10+prot_minor == 10)
          *open = FALSE; /* HTTP 1.0 closes connection by default */

        if(!strncmp(doc, "bad", 3))
          /* if the host name starts with bad, we fake an error here */
          test_no = DOCNUMBER_BADCONNECT;
        else if(!strncmp(doc, "test", 4)) {
          char *ptr = strchr(doc, ':');
          if(ptr)
            test_no = atoi(ptr+1);
          else
            test_no = DOCNUMBER_CONNECT;
        }
        else
          test_no = DOCNUMBER_CONNECT;
      }
      else {
        logmsg("Did not find test number in PATH");
        test_no = DOCNUMBER_404;
      }
    }

    return test_no;
  }
  
  logmsg("Got illegal request");
  fprintf(stderr, "Got illegal request\n");
  return DOCNUMBER_404;
}

/* returns -1 on failure */
static int send_doc(int sock,
                    int doc,
                    int part_no,
                    int *alive) /* keep the connection alive or not */
{
  int written;
  int count;
  const char *buffer;
  char *ptr;
  FILE *stream;
  char *cmd=NULL;
  int cmdsize=0;
  FILE *dump;
  int persistant = TRUE;

  static char weare[256];

  char filename[256];
  char partbuf[80]="data";

  *alive = FALSE;

  if(doc < 0) {
    switch(doc) {
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
    logmsg("Fetch response data, test %d part %d", doc, part_no);

    if(0 != part_no)
      sprintf(partbuf, "data%d", part_no);

    sprintf(filename, TEST_DATA_PATH, path, doc);

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
    logmsg("connection close instruction swsclose found in response");
  }

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

  logmsg("Response sent!");

  if(ptr)
    free(ptr);

  if(cmdsize > 0 ) {
    char command[32];
    int num;
    char *ptr=cmd;
    do {
      if(2 == sscanf(ptr, "%31s %d", command, &num)) {
        if(!strcmp("wait", command))
          sleep(num); /* wait this many seconds */
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

  *alive = persistant;

  return 0;
}

int main(int argc, char *argv[])
{
  struct sockaddr_in me;
  int sock, msgsock, flag;
  unsigned short port = DEFAULT_PORT;
  const char *logfile = DEFAULT_LOGFILE;
  int part_no;
  FILE *pidfile;
  
  if(argc>1) {
    port = atoi(argv[1]);

    if(argc>2) {
      path = argv[2];
    }
  }

  logfp = fopen(logfile, "a");
  if (!logfp) {
    perror(logfile);
    exit(1);
  }

#ifdef HAVE_SIGNAL
  signal(SIGPIPE, sigpipe_handler);
#endif
#ifdef HAVE_SIGINTERRUPT
  siginterrupt(SIGPIPE, 1);
#endif

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("opening stream socket");
    fprintf(logfp, "Error opening socket -- aborting\n");
    fclose(logfp);
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
    fprintf(logfp, "Error binding socket -- aborting\n");
    fclose(logfp);
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
    int doc;
    int open;
    int alive;
    
    msgsock = accept(sock, NULL, NULL);
    
    if (msgsock == -1)
      continue;
    
    logmsg("New client connected");

    do {

      doc = get_request(msgsock, &part_no, &open);
      logmsg("Received request, now send response number %d part %d",
             doc, part_no);
      send_doc(msgsock, doc, part_no, &alive);

      if((doc < 0) && (doc != DOCNUMBER_CONNECT)) {
        logmsg("special request received, no persistancy");
        break;
      }
      if(!alive) {
        logmsg("instructed to close connection after server-reply");
        break;
      }

      if(open)
        logmsg("persistant connection, awaits new request");
      /* if we got a CONNECT, loop and get another request as well! */
    } while(open || (doc == DOCNUMBER_CONNECT));

    logmsg("Closing client connection");
    sclose(msgsock);

    if (doc == DOCNUMBER_QUIT)
      break;
  }
  
  sclose(sock);
  fclose(logfp);
  
  return 0;
}

