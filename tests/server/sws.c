/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "server_setup.h"

/* sws.c: simple (silly?) web server

   This code was originally graciously donated to the project by Juergen
   Wilke. Thanks a bunch!

 */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h> /* for TCP_NODELAY */
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "inet_pton.h"
#include "util.h"
#include "server_sockaddr.h"

/* include memdebug.h last */
#include "memdebug.h"

#ifdef USE_WINSOCK
#undef  EINTR
#define EINTR    4 /* errno.h value */
#undef  EAGAIN
#define EAGAIN  11 /* errno.h value */
#undef  ERANGE
#define ERANGE  34 /* errno.h value */
#endif

static enum {
  socket_domain_inet = AF_INET
#ifdef ENABLE_IPV6
  , socket_domain_inet6 = AF_INET6
#endif
#ifdef USE_UNIX_SOCKETS
  , socket_domain_unix = AF_UNIX
#endif
} socket_domain = AF_INET;
static bool use_gopher = FALSE;
static int serverlogslocked = 0;
static bool is_proxy = FALSE;

#define REQBUFSIZ (2*1024*1024)

#define MAX_SLEEP_TIME_MS 250

static long prevtestno = -1;    /* previous test number we served */
static long prevpartno = -1;    /* previous part number we served */
static bool prevbounce = FALSE; /* instructs the server to increase the part
                                   number for a test in case the identical
                                   testno+partno request shows up again */

#define RCMD_NORMALREQ 0 /* default request, use the tests file normally */
#define RCMD_IDLE      1 /* told to sit idle */
#define RCMD_STREAM    2 /* told to stream */

struct httprequest {
  char reqbuf[REQBUFSIZ]; /* buffer area for the incoming request */
  bool connect_request; /* if a CONNECT */
  unsigned short connect_port; /* the port number CONNECT used */
  size_t checkindex; /* where to start checking of the request */
  size_t offset;     /* size of the incoming request */
  long testno;       /* test number found in the request */
  long partno;       /* part number found in the request */
  bool open;      /* keep connection open info, as found in the request */
  bool auth_req;  /* authentication required, don't wait for body unless
                     there's an Authorization header */
  bool auth;      /* Authorization header present in the incoming request */
  size_t cl;      /* Content-Length of the incoming request */
  bool digest;    /* Authorization digest header found */
  bool ntlm;      /* Authorization ntlm header found */
  int writedelay; /* if non-zero, delay this number of milliseconds between
                     writes in the response */
  int skip;       /* if non-zero, the server is instructed to not read this
                     many bytes from a PUT/POST request. Ie the client sends N
                     bytes said in Content-Length, but the server only reads N
                     - skip bytes. */
  int rcmd;       /* doing a special command, see defines above */
  int prot_version;  /* HTTP version * 10 */
  int callcount;  /* times ProcessRequest() gets called */
  bool skipall;   /* skip all incoming data */
  bool noexpect;  /* refuse Expect: (don't read the body) */
  bool connmon;   /* monitor the state of the connection, log disconnects */
  bool upgrade;   /* test case allows upgrade */
  bool upgrade_request; /* upgrade request found and allowed */
  bool close;     /* similar to swsclose in response: close connection after
                     response is sent */
  int done_processing;
};

#define MAX_SOCKETS 1024

static curl_socket_t all_sockets[MAX_SOCKETS];
static size_t num_sockets = 0;

static int ProcessRequest(struct httprequest *req);
static void storerequest(const char *reqbuf, size_t totalsize);

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sws.log"
#endif

const char *serverlogfile = DEFAULT_LOGFILE;

#define SWSVERSION "curl test suite HTTP server/0.1"

#define REQUEST_DUMP  "log/server.input"
#define RESPONSE_DUMP "log/server.response"

/* when told to run as proxy, we store the logs in different files so that
   they can co-exist with the same program running as a "server" */
#define REQUEST_PROXY_DUMP  "log/proxy.input"
#define RESPONSE_PROXY_DUMP "log/proxy.response"

/* file in which additional instructions may be found */
#define DEFAULT_CMDFILE "log/ftpserver.cmd"
const char *cmdfile = DEFAULT_CMDFILE;

/* very-big-path support */
#define MAXDOCNAMELEN 140000
#define MAXDOCNAMELEN_TXT "139999"

#define REQUEST_KEYWORD_SIZE 256
#define REQUEST_KEYWORD_SIZE_TXT "255"

#define CMD_AUTH_REQUIRED "auth_required"

/* 'idle' means that it will accept the request fine but never respond
   any data. Just keep the connection alive. */
#define CMD_IDLE "idle"

/* 'stream' means to send a never-ending stream of data */
#define CMD_STREAM "stream"

/* 'connection-monitor' will output when a server/proxy connection gets
   disconnected as for some cases it is important that it gets done at the
   proper point - like with NTLM */
#define CMD_CONNECTIONMONITOR "connection-monitor"

/* upgrade to http2/websocket/xxxx */
#define CMD_UPGRADE "upgrade"

/* close connection */
#define CMD_SWSCLOSE "swsclose"

/* deny Expect: requests */
#define CMD_NOEXPECT "no-expect"

#define END_OF_HEADERS "\r\n\r\n"

enum {
  DOCNUMBER_NOTHING = -4,
  DOCNUMBER_QUIT    = -3,
  DOCNUMBER_WERULEZ = -2,
  DOCNUMBER_404     = -1
};

static const char *end_of_headers = END_OF_HEADERS;

/* sent as reply to a QUIT */
static const char *docquit =
"HTTP/1.1 200 Goodbye" END_OF_HEADERS;

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

/* work around for handling trailing headers */
static int already_recv_zeroed_chunk = FALSE;

/* returns true if the current socket is an IP one */
static bool socket_domain_is_ip(void)
{
  switch(socket_domain) {
  case AF_INET:
#ifdef ENABLE_IPV6
  case AF_INET6:
#endif
    return true;
  default:
  /* case AF_UNIX: */
    return false;
  }
}

/* parse the file on disk that might have a test number for us */
static int parse_cmdfile(struct httprequest *req)
{
  FILE *f = fopen(cmdfile, FOPEN_READTEXT);
  if(f) {
    int testnum = DOCNUMBER_NOTHING;
    char buf[256];
    while(fgets(buf, sizeof(buf), f)) {
      if(1 == sscanf(buf, "Testnum %d", &testnum)) {
        logmsg("[%s] cmdfile says testnum %d", cmdfile, testnum);
        req->testno = testnum;
      }
    }
    fclose(f);
  }
  return 0;
}

/* based on the testno, parse the correct server commands */
static int parse_servercmd(struct httprequest *req)
{
  FILE *stream;
  int error;

  stream = test2fopen(req->testno);
  req->close = FALSE;
  req->connmon = FALSE;

  if(!stream) {
    error = errno;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("  Couldn't open test file %ld", req->testno);
    req->open = FALSE; /* closes connection */
    return 1; /* done */
  }
  else {
    char *orgcmd = NULL;
    char *cmd = NULL;
    size_t cmdsize = 0;
    int num = 0;

    /* get the custom server control "commands" */
    error = getpart(&orgcmd, &cmdsize, "reply", "servercmd", stream);
    fclose(stream);
    if(error) {
      logmsg("getpart() failed with error: %d", error);
      req->open = FALSE; /* closes connection */
      return 1; /* done */
    }

    cmd = orgcmd;
    while(cmd && cmdsize) {
      char *check;

      if(!strncmp(CMD_AUTH_REQUIRED, cmd, strlen(CMD_AUTH_REQUIRED))) {
        logmsg("instructed to require authorization header");
        req->auth_req = TRUE;
      }
      else if(!strncmp(CMD_IDLE, cmd, strlen(CMD_IDLE))) {
        logmsg("instructed to idle");
        req->rcmd = RCMD_IDLE;
        req->open = TRUE;
      }
      else if(!strncmp(CMD_STREAM, cmd, strlen(CMD_STREAM))) {
        logmsg("instructed to stream");
        req->rcmd = RCMD_STREAM;
      }
      else if(!strncmp(CMD_CONNECTIONMONITOR, cmd,
                       strlen(CMD_CONNECTIONMONITOR))) {
        logmsg("enabled connection monitoring");
        req->connmon = TRUE;
      }
      else if(!strncmp(CMD_UPGRADE, cmd, strlen(CMD_UPGRADE))) {
        logmsg("enabled upgrade");
        req->upgrade = TRUE;
      }
      else if(!strncmp(CMD_SWSCLOSE, cmd, strlen(CMD_SWSCLOSE))) {
        logmsg("swsclose: close this connection after response");
        req->close = TRUE;
      }
      else if(1 == sscanf(cmd, "skip: %d", &num)) {
        logmsg("instructed to skip this number of bytes %d", num);
        req->skip = num;
      }
      else if(!strncmp(CMD_NOEXPECT, cmd, strlen(CMD_NOEXPECT))) {
        logmsg("instructed to reject Expect: 100-continue");
        req->noexpect = TRUE;
      }
      else if(1 == sscanf(cmd, "writedelay: %d", &num)) {
        logmsg("instructed to delay %d msecs between packets", num);
        req->writedelay = num;
      }
      else {
        logmsg("Unknown <servercmd> instruction found: %s", cmd);
      }
      /* try to deal with CRLF or just LF */
      check = strchr(cmd, '\r');
      if(!check)
        check = strchr(cmd, '\n');

      if(check) {
        /* get to the letter following the newline */
        while((*check == '\r') || (*check == '\n'))
          check++;

        if(!*check)
          /* if we reached a zero, get out */
          break;
        cmd = check;
      }
      else
        break;
    }
    free(orgcmd);
  }

  return 0; /* OK! */
}

static int ProcessRequest(struct httprequest *req)
{
  char *line = &req->reqbuf[req->checkindex];
  bool chunked = FALSE;
  static char request[REQUEST_KEYWORD_SIZE];
  char logbuf[456];
  int prot_major = 0;
  int prot_minor = 0;
  char *end = strstr(line, end_of_headers);

  req->callcount++;

  logmsg("Process %d bytes request%s", req->offset,
         req->callcount > 1?" [CONTINUED]":"");

  /* try to figure out the request characteristics as soon as possible, but
     only once! */

  if(use_gopher &&
     (req->testno == DOCNUMBER_NOTHING) &&
     !strncmp("/verifiedserver", line, 15)) {
    logmsg("Are-we-friendly question received");
    req->testno = DOCNUMBER_WERULEZ;
    return 1; /* done */
  }

  else if(req->testno == DOCNUMBER_NOTHING) {
    char *http;
    bool fine = FALSE;
    char *httppath = NULL;
    size_t npath = 0; /* httppath length */

    if(sscanf(line,
              "%" REQUEST_KEYWORD_SIZE_TXT"s ", request)) {
      http = strstr(line + strlen(request), "HTTP/");

      if(http && sscanf(http, "HTTP/%d.%d",
                        &prot_major,
                        &prot_minor) == 2) {
        /* between the request keyword and HTTP/ there's a path */
        httppath = line + strlen(request);
        npath = http - httppath;

        /* trim leading spaces */
        while(npath && ISSPACE(*httppath)) {
          httppath++;
          npath--;
        }
        /* trim ending spaces */
        while(npath && ISSPACE(httppath[npath - 1])) {
          npath--;
        }
        if(npath)
          fine = TRUE;
      }
    }

    if(fine) {
      char *ptr;

      req->prot_version = prot_major*10 + prot_minor;

      /* find the last slash */
      ptr = &httppath[npath];
      while(ptr >= httppath) {
        if(*ptr == '/')
          break;
        ptr--;
      }

      /* get the number after it */
      if(*ptr == '/') {
        if((npath + strlen(request)) < 400)
          msnprintf(logbuf, sizeof(logbuf), "Got request: %s %.*s HTTP/%d.%d",
                    request, npath, httppath, prot_major, prot_minor);
        else
          msnprintf(logbuf, sizeof(logbuf), "Got a *HUGE* request HTTP/%d.%d",
                    prot_major, prot_minor);
        logmsg("%s", logbuf);

        if(!strncmp("/verifiedserver", ptr, 15)) {
          logmsg("Are-we-friendly question received");
          req->testno = DOCNUMBER_WERULEZ;
          return 1; /* done */
        }

        if(!strncmp("/quit", ptr, 5)) {
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

        if(req->testno) {

          msnprintf(logbuf, sizeof(logbuf), "Serve test number %ld part %ld",
                    req->testno, req->partno);
          logmsg("%s", logbuf);
        }
        else {
          logmsg("No test number in path");
          req->testno = DOCNUMBER_NOTHING;
        }

      }

      if(req->testno == DOCNUMBER_NOTHING) {
        /* didn't find any in the first scan, try alternative test case
           number placements */
        static char doc[MAXDOCNAMELEN];
        if(sscanf(req->reqbuf, "CONNECT %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
                  doc, &prot_major, &prot_minor) == 3) {
          char *portp = NULL;

          msnprintf(logbuf, sizeof(logbuf),
                    "Received a CONNECT %s HTTP/%d.%d request",
                    doc, prot_major, prot_minor);
          logmsg("%s", logbuf);

          req->connect_request = TRUE;

          if(req->prot_version == 10)
            req->open = FALSE; /* HTTP 1.0 closes connection by default */

          if(doc[0] == '[') {
            char *p = &doc[1];
            unsigned long part = 0;
            /* scan through the hexgroups and store the value of the last group
               in the 'part' variable and use as test case number!! */
            while(*p && (ISXDIGIT(*p) || (*p == ':') || (*p == '.'))) {
              char *endp;
              part = strtoul(p, &endp, 16);
              if(ISXDIGIT(*p))
                p = endp;
              else
                p++;
            }
            if(*p != ']')
              logmsg("Invalid CONNECT IPv6 address format");
            else if(*(p + 1) != ':')
              logmsg("Invalid CONNECT IPv6 port format");
            else
              portp = p + 1;

            req->testno = part;
          }
          else
            portp = strchr(doc, ':');

          if(portp && (*(portp + 1) != '\0') && ISDIGIT(*(portp + 1))) {
            unsigned long ulnum = strtoul(portp + 1, NULL, 10);
            if(!ulnum || (ulnum > 65535UL))
              logmsg("Invalid CONNECT port received");
            else
              req->connect_port = curlx_ultous(ulnum);

          }
          logmsg("Port number: %d, test case number: %ld",
                 req->connect_port, req->testno);
        }
      }

      if(req->testno == DOCNUMBER_NOTHING)
        /* might get the test number */
        parse_cmdfile(req);

      if(req->testno == DOCNUMBER_NOTHING) {
        logmsg("Did not find test number in PATH");
        req->testno = DOCNUMBER_404;
      }
      else
        parse_servercmd(req);
    }
    else if((req->offset >= 3)) {
      unsigned char *l = (unsigned char *)line;
      logmsg("** Unusual request. Starts with %02x %02x %02x (%c%c%c)",
             l[0], l[1], l[2], l[0], l[1], l[2]);
    }
  }

  if(!end) {
    /* we don't have a complete request yet! */
    logmsg("request not complete yet");
    return 0; /* not complete yet */
  }
  logmsg("- request found to be complete (%d)", req->testno);

  if(req->testno == DOCNUMBER_NOTHING) {
    /* check for a Testno: header with the test case number */
    char *testno = strstr(line, "\nTestno: ");
    if(testno) {
      req->testno = strtol(&testno[9], NULL, 10);
      logmsg("Found test number %d in Testno: header!", req->testno);
    }
    else {
      logmsg("No Testno: header");
    }
  }

  /* find and parse <servercmd> for this test */
  parse_servercmd(req);

  if(use_gopher) {
    /* when using gopher we cannot check the request until the entire
       thing has been received */
    char *ptr;

    /* find the last slash in the line */
    ptr = strrchr(line, '/');

    if(ptr) {
      ptr++; /* skip the slash */

      /* skip all non-numericals following the slash */
      while(*ptr && !ISDIGIT(*ptr))
        ptr++;

      req->testno = strtol(ptr, &ptr, 10);

      if(req->testno > 10000) {
        req->partno = req->testno % 10000;
        req->testno /= 10000;
      }
      else
        req->partno = 0;

      msnprintf(logbuf, sizeof(logbuf),
                "Requested GOPHER test number %ld part %ld",
                req->testno, req->partno);
      logmsg("%s", logbuf);
    }
  }

  /* **** Persistence ****
   *
   * If the request is an HTTP/1.0 one, we close the connection unconditionally
   * when we're done.
   *
   * If the request is an HTTP/1.1 one, we MUST check for a "Connection:"
   * header that might say "close". If it does, we close a connection when
   * this request is processed. Otherwise, we keep the connection alive for X
   * seconds.
   */

  do {
    if(got_exit_signal)
      return 1; /* done */

    if((req->cl == 0) && strncasecompare("Content-Length:", line, 15)) {
      /* If we don't ignore content-length, we read it and we read the whole
         request including the body before we return. If we've been told to
         ignore the content-length, we will return as soon as all headers
         have been received */
      char *endptr;
      char *ptr = line + 15;
      unsigned long clen = 0;
      while(*ptr && ISSPACE(*ptr))
        ptr++;
      endptr = ptr;
      errno = 0;
      clen = strtoul(ptr, &endptr, 10);
      if((ptr == endptr) || !ISSPACE(*endptr) || (ERANGE == errno)) {
        /* this assumes that a zero Content-Length is valid */
        logmsg("Found invalid Content-Length: (%s) in the request", ptr);
        req->open = FALSE; /* closes connection */
        return 1; /* done */
      }
      if(req->skipall)
        req->cl = 0;
      else
        req->cl = clen - req->skip;

      logmsg("Found Content-Length: %lu in the request", clen);
      if(req->skip)
        logmsg("... but will abort after %zu bytes", req->cl);
    }
    else if(strncasecompare("Transfer-Encoding: chunked", line,
                            strlen("Transfer-Encoding: chunked"))) {
      /* chunked data coming in */
      chunked = TRUE;
    }
    else if(req->noexpect &&
            strncasecompare("Expect: 100-continue", line,
                            strlen("Expect: 100-continue"))) {
      if(req->cl)
        req->cl = 0;
      req->skipall = TRUE;
      logmsg("Found Expect: 100-continue, ignore body");
    }

    if(chunked) {
      if(strstr(req->reqbuf, "\r\n0\r\n\r\n")) {
        /* end of chunks reached */
        return 1; /* done */
      }
      else if(strstr(req->reqbuf, "\r\n0\r\n")) {
        char *last_crlf_char = strstr(req->reqbuf, "\r\n\r\n");
        while(TRUE) {
          if(!strstr(last_crlf_char + 4, "\r\n\r\n"))
            break;
          last_crlf_char = strstr(last_crlf_char + 4, "\r\n\r\n");
        }
        if(last_crlf_char &&
           last_crlf_char > strstr(req->reqbuf, "\r\n0\r\n"))
          return 1;
        already_recv_zeroed_chunk = TRUE;
        return 0;
      }
      else if(already_recv_zeroed_chunk && strstr(req->reqbuf, "\r\n\r\n"))
        return 1;
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

  if(strstr(req->reqbuf, "Authorization: Negotiate")) {
    /* Negotiate iterations */
    static long prev_testno = -1;
    static long prev_partno = -1;
    logmsg("Negotiate: prev_testno: %d, prev_partno: %d",
            prev_testno, prev_partno);
    if(req->testno != prev_testno) {
      prev_testno = req->testno;
      prev_partno = req->partno;
    }
    prev_partno += 1;
    req->partno = prev_partno;
  }
  else if(!req->digest && strstr(req->reqbuf, "Authorization: Digest")) {
    /* If the client is passing this Digest-header, we set the part number
       to 1000. Not only to spice up the complexity of this, but to make
       Digest stuff to work in the test suite. */
    req->partno += 1000;
    req->digest = TRUE; /* header found */
    logmsg("Received Digest request, sending back data %ld", req->partno);
  }
  else if(!req->ntlm &&
          strstr(req->reqbuf, "Authorization: NTLM TlRMTVNTUAAD")) {
    /* If the client is passing this type-3 NTLM header */
    req->partno += 1002;
    req->ntlm = TRUE; /* NTLM found */
    logmsg("Received NTLM type-3, sending back data %ld", req->partno);
    if(req->cl) {
      logmsg("  Expecting %zu POSTed bytes", req->cl);
    }
  }
  else if(!req->ntlm &&
          strstr(req->reqbuf, "Authorization: NTLM TlRMTVNTUAAB")) {
    /* If the client is passing this type-1 NTLM header */
    req->partno += 1001;
    req->ntlm = TRUE; /* NTLM found */
    logmsg("Received NTLM type-1, sending back data %ld", req->partno);
  }
  else if((req->partno >= 1000) &&
          strstr(req->reqbuf, "Authorization: Basic")) {
    /* If the client is passing this Basic-header and the part number is
       already >=1000, we add 1 to the part number.  This allows simple Basic
       authentication negotiation to work in the test suite. */
    req->partno += 1;
    logmsg("Received Basic request, sending back data %ld", req->partno);
  }
  if(strstr(req->reqbuf, "Connection: close"))
    req->open = FALSE; /* close connection after this request */

  if(req->open &&
     req->prot_version >= 11 &&
     req->reqbuf + req->offset > end + strlen(end_of_headers) &&
     !req->cl &&
     (!strncmp(req->reqbuf, "GET", strlen("GET")) ||
      !strncmp(req->reqbuf, "HEAD", strlen("HEAD")))) {
    /* If we have a persistent connection, HTTP version >= 1.1
       and GET/HEAD request, enable pipelining. */
    req->checkindex = (end - req->reqbuf) + strlen(end_of_headers);
  }

  /* If authentication is required and no auth was provided, end now. This
     makes the server NOT wait for PUT/POST data and you can then make the
     test case send a rejection before any such data has been sent. Test case
     154 uses this.*/
  if(req->auth_req && !req->auth) {
    logmsg("Return early due to auth requested by none provided");
    return 1; /* done */
  }

  if(req->upgrade && strstr(req->reqbuf, "Upgrade:")) {
    /* we allow upgrade and there was one! */
    logmsg("Found Upgrade: in request and allow it");
    req->upgrade_request = TRUE;
    return 0; /* not done */
  }

  if(req->cl > 0) {
    if(req->cl <= req->offset - (end - req->reqbuf) - strlen(end_of_headers))
      return 1; /* done */
    else
      return 0; /* not complete yet */
  }

  return 1; /* done */
}

/* store the entire request in a file */
static void storerequest(const char *reqbuf, size_t totalsize)
{
  int res;
  int error = 0;
  size_t written;
  size_t writeleft;
  FILE *dump;
  const char *dumpfile = is_proxy?REQUEST_PROXY_DUMP:REQUEST_DUMP;

  if(!reqbuf)
    return;
  if(totalsize == 0)
    return;

  do {
    dump = fopen(dumpfile, "ab");
  } while(!dump && ((error = errno) == EINTR));
  if(!dump) {
    logmsg("[2] Error opening file %s error: %d %s",
           dumpfile, error, strerror(error));
    logmsg("Failed to write request input ");
    return;
  }

  writeleft = totalsize;
  do {
    written = fwrite(&reqbuf[totalsize-writeleft],
                     1, writeleft, dump);
    if(got_exit_signal)
      goto storerequest_cleanup;
    if(written > 0)
      writeleft -= written;
  } while((writeleft > 0) && ((error = errno) == EINTR));

  if(writeleft == 0)
    logmsg("Wrote request (%zu bytes) input to %s", totalsize, dumpfile);
  else if(writeleft > 0) {
    logmsg("Error writing file %s error: %d %s",
           dumpfile, error, strerror(error));
    logmsg("Wrote only (%zu bytes) of (%zu bytes) request input to %s",
           totalsize-writeleft, totalsize, dumpfile);
  }

storerequest_cleanup:

  do {
    res = fclose(dump);
  } while(res && ((error = errno) == EINTR));
  if(res)
    logmsg("Error closing file %s error: %d %s",
           dumpfile, error, strerror(error));
}

static void init_httprequest(struct httprequest *req)
{
  req->checkindex = 0;
  req->offset = 0;
  req->testno = DOCNUMBER_NOTHING;
  req->partno = 0;
  req->connect_request = FALSE;
  req->open = TRUE;
  req->auth_req = FALSE;
  req->auth = FALSE;
  req->cl = 0;
  req->digest = FALSE;
  req->ntlm = FALSE;
  req->skip = 0;
  req->skipall = FALSE;
  req->noexpect = FALSE;
  req->writedelay = 0;
  req->rcmd = RCMD_NORMALREQ;
  req->prot_version = 0;
  req->callcount = 0;
  req->connect_port = 0;
  req->done_processing = 0;
  req->upgrade = 0;
  req->upgrade_request = 0;
}

static int send_doc(curl_socket_t sock, struct httprequest *req);

/* returns 1 if the connection should be serviced again immediately, 0 if there
   is no data waiting, or < 0 if it should be closed */
static int get_request(curl_socket_t sock, struct httprequest *req)
{
  int fail = 0;
  char *reqbuf = req->reqbuf;
  ssize_t got = 0;
  int overflow = 0;

  if(req->upgrade_request) {
    /* upgraded connection, work it differently until end of connection */
    logmsg("Upgraded connection, this is a no longer HTTP/1");
    send_doc(sock, req);

    /* dump the request received so far to the external file */
    reqbuf[req->offset] = '\0';
    storerequest(reqbuf, req->offset);
    req->offset = 0;

    /* read websocket traffic */
    if(req->open)
      do {

      got = sread(sock, reqbuf + req->offset, REQBUFSIZ - req->offset);
      if(got > 0)
        req->offset += got;

      if((got == -1) && ((EAGAIN == errno) || (EWOULDBLOCK == errno))) {
        int rc;
        fd_set input;
        fd_set output;
        struct timeval timeout = {1, 0}; /* 1000 ms */

        logmsg("Got EAGAIN from sread");
        FD_ZERO(&input);
        FD_ZERO(&output);
        got = 0;
        FD_SET(sock, &input);
        do {
          logmsg("Wait until readable");
          rc = select((int)sock + 1, &input, &output, NULL, &timeout);
        } while(rc < 0 && errno == EINTR && !got_exit_signal);
        logmsg("readable %d", rc);
        if(rc)
          got = 1;
      }
    } while(got > 0);

    if(req->offset) {
      logmsg("log the websocket traffic");
      /* dump the incoming websocket traffic to the external file */
      reqbuf[req->offset] = '\0';
      storerequest(reqbuf, req->offset);
      req->offset = 0;
    }
    init_httprequest(req);

    return -1;
  }

  if(req->offset >= REQBUFSIZ-1) {
    /* buffer is already full; do nothing */
    overflow = 1;
  }
  else {
    if(req->skip)
      /* we are instructed to not read the entire thing, so we make sure to
         only read what we're supposed to and NOT read the entire thing the
         client wants to send! */
      got = sread(sock, reqbuf + req->offset, req->cl);
    else
      got = sread(sock, reqbuf + req->offset, REQBUFSIZ-1 - req->offset);

    if(got_exit_signal)
      return -1;
    if(got == 0) {
      logmsg("Connection closed by client");
      fail = 1;
    }
    else if(got < 0) {
      int error = SOCKERRNO;
      if(EAGAIN == error || EWOULDBLOCK == error) {
        /* nothing to read at the moment */
        return 0;
      }
      logmsg("recv() returned error: (%d) %s", error, strerror(error));
      fail = 1;
    }
    if(fail) {
      /* dump the request received so far to the external file */
      reqbuf[req->offset] = '\0';
      storerequest(reqbuf, req->offset);
      return -1;
    }

    logmsg("Read %zd bytes", got);

    req->offset += (size_t)got;
    reqbuf[req->offset] = '\0';

    req->done_processing = ProcessRequest(req);
    if(got_exit_signal)
      return -1;
  }

  if(overflow || (req->offset == REQBUFSIZ-1 && got > 0)) {
    logmsg("Request would overflow buffer, closing connection");
    /* dump request received so far to external file anyway */
    reqbuf[REQBUFSIZ-1] = '\0';
    fail = 1;
  }
  else if(req->offset > REQBUFSIZ-1) {
    logmsg("Request buffer overflow, closing connection");
    /* dump request received so far to external file anyway */
    reqbuf[REQBUFSIZ-1] = '\0';
    fail = 1;
  }
  else
    reqbuf[req->offset] = '\0';

  /* at the end of a request dump it to an external file */
  if(fail || req->done_processing)
    storerequest(reqbuf, req->offset);
  if(got_exit_signal)
    return -1;

  return fail ? -1 : 1;
}

/* returns -1 on failure */
static int send_doc(curl_socket_t sock, struct httprequest *req)
{
  ssize_t written;
  size_t count;
  const char *buffer;
  char *ptr = NULL;
  FILE *stream;
  char *cmd = NULL;
  size_t cmdsize = 0;
  FILE *dump;
  bool persistent = TRUE;
  bool sendfailure = FALSE;
  size_t responsesize;
  int error = 0;
  int res;
  const char *responsedump = is_proxy?RESPONSE_PROXY_DUMP:RESPONSE_DUMP;
  static char weare[256];

  switch(req->rcmd) {
  default:
  case RCMD_NORMALREQ:
    break; /* continue with business as usual */
  case RCMD_STREAM:
#define STREAMTHIS "a string to stream 01234567890\n"
    count = strlen(STREAMTHIS);
    for(;;) {
      written = swrite(sock, STREAMTHIS, count);
      if(got_exit_signal)
        return -1;
      if(written != (ssize_t)count) {
        logmsg("Stopped streaming");
        break;
      }
    }
    return -1;
  case RCMD_IDLE:
    /* Do nothing. Sit idle. Pretend it rains. */
    return 0;
  }

  req->open = FALSE;

  if(req->testno < 0) {
    size_t msglen;
    char msgbuf[64];

    switch(req->testno) {
    case DOCNUMBER_QUIT:
      logmsg("Replying to QUIT");
      buffer = docquit;
      break;
    case DOCNUMBER_WERULEZ:
      /* we got a "friends?" question, reply back that we sure are */
      logmsg("Identifying ourselves as friends");
      msnprintf(msgbuf, sizeof(msgbuf), "WE ROOLZ: %"
                CURL_FORMAT_CURL_OFF_T "\r\n", our_getpid());
      msglen = strlen(msgbuf);
      if(use_gopher)
        msnprintf(weare, sizeof(weare), "%s", msgbuf);
      else
        msnprintf(weare, sizeof(weare),
                  "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s",
                  msglen, msgbuf);
      buffer = weare;
      break;
    case DOCNUMBER_404:
    default:
      logmsg("Replying to with a 404");
      buffer = doc404;
      break;
    }

    count = strlen(buffer);
  }
  else {
    char partbuf[80];

    /* select the <data> tag for "normal" requests and the <connect> one
       for CONNECT requests (within the <reply> section) */
    const char *section = req->connect_request?"connect":"data";

    if(req->partno)
      msnprintf(partbuf, sizeof(partbuf), "%s%ld", section, req->partno);
    else
      msnprintf(partbuf, sizeof(partbuf), "%s", section);

    logmsg("Send response test%ld section <%s>", req->testno, partbuf);

    stream = test2fopen(req->testno);
    if(!stream) {
      error = errno;
      logmsg("fopen() failed with error: %d %s", error, strerror(error));
      return 0;
    }
    else {
      error = getpart(&ptr, &count, "reply", partbuf, stream);
      fclose(stream);
      if(error) {
        logmsg("getpart() failed with error: %d", error);
        return 0;
      }
      buffer = ptr;
    }

    if(got_exit_signal) {
      free(ptr);
      return -1;
    }

    /* re-open the same file again */
    stream = test2fopen(req->testno);
    if(!stream) {
      error = errno;
      logmsg("fopen() failed with error: %d %s", error, strerror(error));
      free(ptr);
      return 0;
    }
    else {
      /* get the custom server control "commands" */
      error = getpart(&cmd, &cmdsize, "reply", "postcmd", stream);
      fclose(stream);
      if(error) {
        logmsg("getpart() failed with error: %d", error);
        free(ptr);
        return 0;
      }
    }
  }

  if(got_exit_signal) {
    free(ptr);
    free(cmd);
    return -1;
  }

  /* If the word 'swsclose' is present anywhere in the reply chunk, the
     connection will be closed after the data has been sent to the requesting
     client... */
  if(strstr(buffer, "swsclose") || !count || req->close) {
    persistent = FALSE;
    logmsg("connection close instruction \"swsclose\" found in response");
  }
  if(strstr(buffer, "swsbounce")) {
    prevbounce = TRUE;
    logmsg("enable \"swsbounce\" in the next request");
  }
  else
    prevbounce = FALSE;

  dump = fopen(responsedump, "ab");
  if(!dump) {
    error = errno;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("  [5] Error opening file: %s", responsedump);
    free(ptr);
    free(cmd);
    return -1;
  }

  responsesize = count;
  do {
    /* Ok, we send no more than N bytes at a time, just to make sure that
       larger chunks are split up so that the client will need to do multiple
       recv() calls to get it and thus we exercise that code better */
    size_t num = count;
    if(num > 20)
      num = 20;

    retry:
    written = swrite(sock, buffer, num);
    if(written < 0) {
      if((EWOULDBLOCK == SOCKERRNO) || (EAGAIN == SOCKERRNO)) {
        wait_ms(10);
        goto retry;
      }
      sendfailure = TRUE;
      break;
    }

    /* write to file as well */
    fwrite(buffer, 1, (size_t)written, dump);

    count -= written;
    buffer += written;

    if(req->writedelay) {
      int msecs_left = req->writedelay;
      int intervals = msecs_left / MAX_SLEEP_TIME_MS;
      if(msecs_left%MAX_SLEEP_TIME_MS)
        intervals++;
      logmsg("Pausing %d milliseconds after writing %d bytes",
         msecs_left, written);
      while((intervals > 0) && !got_exit_signal) {
        int sleep_time = msecs_left > MAX_SLEEP_TIME_MS ?
          MAX_SLEEP_TIME_MS : msecs_left;
        intervals--;
        wait_ms(sleep_time);
        msecs_left -= sleep_time;
      }
    }
  } while((count > 0) && !got_exit_signal);

  do {
    res = fclose(dump);
  } while(res && ((error = errno) == EINTR));
  if(res)
    logmsg("Error closing file %s error: %d %s",
           responsedump, error, strerror(error));

  if(got_exit_signal) {
    free(ptr);
    free(cmd);
    return -1;
  }

  if(sendfailure) {
    logmsg("Sending response failed. Only (%zu bytes) of (%zu bytes) "
           "were sent",
           responsesize-count, responsesize);
    prevtestno = req->testno;
    prevpartno = req->partno;
    free(ptr);
    free(cmd);
    return -1;
  }

  logmsg("Response sent (%zu bytes) and written to %s",
         responsesize, responsedump);
  free(ptr);

  if(cmdsize > 0) {
    char command[32];
    int quarters;
    int num;
    ptr = cmd;
    do {
      if(2 == sscanf(ptr, "%31s %d", command, &num)) {
        if(!strcmp("wait", command)) {
          logmsg("Told to sleep for %d seconds", num);
          quarters = num * 4;
          while((quarters > 0) && !got_exit_signal) {
            quarters--;
            res = wait_ms(250);
            if(res) {
              /* should not happen */
              error = errno;
              logmsg("wait_ms() failed with error: (%d) %s",
                     error, strerror(error));
              break;
            }
          }
          if(!quarters)
            logmsg("Continuing after sleeping %d seconds", num);
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
  free(cmd);
  req->open = use_gopher?FALSE:persistent;

  prevtestno = req->testno;
  prevpartno = req->partno;

  return 0;
}

static curl_socket_t connect_to(const char *ipaddr, unsigned short port)
{
  srvr_sockaddr_union_t serveraddr;
  curl_socket_t serverfd;
  int error;
  int rc = 0;
  const char *op_br = "";
  const char *cl_br = "";

#ifdef ENABLE_IPV6
  if(socket_domain == AF_INET6) {
    op_br = "[";
    cl_br = "]";
  }
#endif

  if(!ipaddr)
    return CURL_SOCKET_BAD;

  logmsg("about to connect to %s%s%s:%hu",
         op_br, ipaddr, cl_br, port);


  serverfd = socket(socket_domain, SOCK_STREAM, 0);
  if(CURL_SOCKET_BAD == serverfd) {
    error = SOCKERRNO;
    logmsg("Error creating socket for server connection: (%d) %s",
           error, strerror(error));
    return CURL_SOCKET_BAD;
  }

#ifdef TCP_NODELAY
  if(socket_domain_is_ip()) {
    /* Disable the Nagle algorithm */
    curl_socklen_t flag = 1;
    if(0 != setsockopt(serverfd, IPPROTO_TCP, TCP_NODELAY,
                       (void *)&flag, sizeof(flag)))
      logmsg("====> TCP_NODELAY for server connection failed");
  }
#endif

  switch(socket_domain) {
  case AF_INET:
    memset(&serveraddr.sa4, 0, sizeof(serveraddr.sa4));
    serveraddr.sa4.sin_family = AF_INET;
    serveraddr.sa4.sin_port = htons(port);
    if(Curl_inet_pton(AF_INET, ipaddr, &serveraddr.sa4.sin_addr) < 1) {
      logmsg("Error inet_pton failed AF_INET conversion of '%s'", ipaddr);
      sclose(serverfd);
      return CURL_SOCKET_BAD;
    }

    rc = connect(serverfd, &serveraddr.sa, sizeof(serveraddr.sa4));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    memset(&serveraddr.sa6, 0, sizeof(serveraddr.sa6));
    serveraddr.sa6.sin6_family = AF_INET6;
    serveraddr.sa6.sin6_port = htons(port);
    if(Curl_inet_pton(AF_INET6, ipaddr, &serveraddr.sa6.sin6_addr) < 1) {
      logmsg("Error inet_pton failed AF_INET6 conversion of '%s'", ipaddr);
      sclose(serverfd);
      return CURL_SOCKET_BAD;
    }

    rc = connect(serverfd, &serveraddr.sa, sizeof(serveraddr.sa6));
    break;
#endif /* ENABLE_IPV6 */
#ifdef USE_UNIX_SOCKETS
  case AF_UNIX:
    logmsg("Proxying through Unix socket is not (yet?) supported.");
    return CURL_SOCKET_BAD;
#endif /* USE_UNIX_SOCKETS */
  }

  if(got_exit_signal) {
    sclose(serverfd);
    return CURL_SOCKET_BAD;
  }

  if(rc) {
    error = SOCKERRNO;
    logmsg("Error connecting to server port %hu: (%d) %s",
           port, error, strerror(error));
    sclose(serverfd);
    return CURL_SOCKET_BAD;
  }

  logmsg("connected fine to %s%s%s:%hu, now tunnel",
         op_br, ipaddr, cl_br, port);

  return serverfd;
}

/*
 * A CONNECT has been received, a CONNECT response has been sent.
 *
 * This function needs to connect to the server, and then pass data between
 * the client and the server back and forth until the connection is closed by
 * either end.
 *
 * When doing FTP through a CONNECT proxy, we expect that the data connection
 * will be setup while the first connect is still being kept up. Therefore we
 * must accept a new connection and deal with it appropriately.
 */

#define data_or_ctrl(x) ((x)?"DATA":"CTRL")

#define CTRL  0
#define DATA  1

static void http_connect(curl_socket_t *infdp,
                         curl_socket_t rootfd,
                         const char *ipaddr,
                         unsigned short ipport)
{
  curl_socket_t serverfd[2] = {CURL_SOCKET_BAD, CURL_SOCKET_BAD};
  curl_socket_t clientfd[2] = {CURL_SOCKET_BAD, CURL_SOCKET_BAD};
  ssize_t toc[2] = {0, 0}; /* number of bytes to client */
  ssize_t tos[2] = {0, 0}; /* number of bytes to server */
  char readclient[2][256];
  char readserver[2][256];
  bool poll_client_rd[2] = { TRUE, TRUE };
  bool poll_server_rd[2] = { TRUE, TRUE };
  bool poll_client_wr[2] = { TRUE, TRUE };
  bool poll_server_wr[2] = { TRUE, TRUE };
  bool primary = FALSE;
  bool secondary = FALSE;
  int max_tunnel_idx; /* CTRL or DATA */
  int loop;
  int i;
  int timeout_count = 0;

  /* primary tunnel client endpoint already connected */
  clientfd[CTRL] = *infdp;

  /* Sleep here to make sure the client reads CONNECT response's
     'end of headers' separate from the server data that follows.
     This is done to prevent triggering libcurl known bug #39. */
  for(loop = 2; (loop > 0) && !got_exit_signal; loop--)
    wait_ms(250);
  if(got_exit_signal)
    goto http_connect_cleanup;

  serverfd[CTRL] = connect_to(ipaddr, ipport);
  if(serverfd[CTRL] == CURL_SOCKET_BAD)
    goto http_connect_cleanup;

  /* Primary tunnel socket endpoints are now connected. Tunnel data back and
     forth over the primary tunnel until client or server breaks the primary
     tunnel, simultaneously allowing establishment, operation and teardown of
     a secondary tunnel that may be used for passive FTP data connection. */

  max_tunnel_idx = CTRL;
  primary = TRUE;

  while(!got_exit_signal) {

    fd_set input;
    fd_set output;
    struct timeval timeout = {1, 0}; /* 1000 ms */
    ssize_t rc;
    curl_socket_t maxfd = (curl_socket_t)-1;

    FD_ZERO(&input);
    FD_ZERO(&output);

    if((clientfd[DATA] == CURL_SOCKET_BAD) &&
       (serverfd[DATA] == CURL_SOCKET_BAD) &&
       poll_client_rd[CTRL] && poll_client_wr[CTRL] &&
       poll_server_rd[CTRL] && poll_server_wr[CTRL]) {
      /* listener socket is monitored to allow client to establish
         secondary tunnel only when this tunnel is not established
         and primary one is fully operational */
      FD_SET(rootfd, &input);
      maxfd = rootfd;
    }

    /* set tunnel sockets to wait for */
    for(i = 0; i <= max_tunnel_idx; i++) {
      /* client side socket monitoring */
      if(clientfd[i] != CURL_SOCKET_BAD) {
        if(poll_client_rd[i]) {
          /* unless told not to do so, monitor readability */
          FD_SET(clientfd[i], &input);
          if(clientfd[i] > maxfd)
            maxfd = clientfd[i];
        }
        if(poll_client_wr[i] && toc[i]) {
          /* unless told not to do so, monitor writability
             if there is data ready to be sent to client */
          FD_SET(clientfd[i], &output);
          if(clientfd[i] > maxfd)
            maxfd = clientfd[i];
        }
      }
      /* server side socket monitoring */
      if(serverfd[i] != CURL_SOCKET_BAD) {
        if(poll_server_rd[i]) {
          /* unless told not to do so, monitor readability */
          FD_SET(serverfd[i], &input);
          if(serverfd[i] > maxfd)
            maxfd = serverfd[i];
        }
        if(poll_server_wr[i] && tos[i]) {
          /* unless told not to do so, monitor writability
             if there is data ready to be sent to server */
          FD_SET(serverfd[i], &output);
          if(serverfd[i] > maxfd)
            maxfd = serverfd[i];
        }
      }
    }
    if(got_exit_signal)
      break;

    do {
      rc = select((int)maxfd + 1, &input, &output, NULL, &timeout);
    } while(rc < 0 && errno == EINTR && !got_exit_signal);

    if(got_exit_signal)
      break;

    if(rc > 0) {
      /* socket action */
      bool tcp_fin_wr = FALSE;
      timeout_count = 0;

      /* ---------------------------------------------------------- */

      /* passive mode FTP may establish a secondary tunnel */
      if((clientfd[DATA] == CURL_SOCKET_BAD) &&
         (serverfd[DATA] == CURL_SOCKET_BAD) && FD_ISSET(rootfd, &input)) {
        /* a new connection on listener socket (most likely from client) */
        curl_socket_t datafd = accept(rootfd, NULL, NULL);
        if(datafd != CURL_SOCKET_BAD) {
          static struct httprequest *req2;
          int err = 0;
          if(!req2) {
            req2 = malloc(sizeof(*req2));
            if(!req2)
              exit(1);
          }
          memset(req2, 0, sizeof(*req2));
          logmsg("====> Client connect DATA");
#ifdef TCP_NODELAY
          if(socket_domain_is_ip()) {
            /* Disable the Nagle algorithm */
            curl_socklen_t flag = 1;
            if(0 != setsockopt(datafd, IPPROTO_TCP, TCP_NODELAY,
                               (void *)&flag, sizeof(flag)))
              logmsg("====> TCP_NODELAY for client DATA connection failed");
          }
#endif
          init_httprequest(req2);
          while(!req2->done_processing) {
            err = get_request(datafd, req2);
            if(err < 0) {
              /* this socket must be closed, done or not */
              break;
            }
          }

          /* skip this and close the socket if err < 0 */
          if(err >= 0) {
            err = send_doc(datafd, req2);
            if(!err && req2->connect_request) {
              /* sleep to prevent triggering libcurl known bug #39. */
              for(loop = 2; (loop > 0) && !got_exit_signal; loop--)
                wait_ms(250);
              if(!got_exit_signal) {
                /* connect to the server */
                serverfd[DATA] = connect_to(ipaddr, req2->connect_port);
                if(serverfd[DATA] != CURL_SOCKET_BAD) {
                  /* secondary tunnel established, now we have two
                     connections */
                  poll_client_rd[DATA] = TRUE;
                  poll_client_wr[DATA] = TRUE;
                  poll_server_rd[DATA] = TRUE;
                  poll_server_wr[DATA] = TRUE;
                  max_tunnel_idx = DATA;
                  secondary = TRUE;
                  toc[DATA] = 0;
                  tos[DATA] = 0;
                  clientfd[DATA] = datafd;
                  datafd = CURL_SOCKET_BAD;
                }
              }
            }
          }
          if(datafd != CURL_SOCKET_BAD) {
            /* secondary tunnel not established */
            shutdown(datafd, SHUT_RDWR);
            sclose(datafd);
          }
        }
        if(got_exit_signal)
          break;
      }

      /* ---------------------------------------------------------- */

      /* react to tunnel endpoint readable/writable notifications */
      for(i = 0; i <= max_tunnel_idx; i++) {
        size_t len;
        if(clientfd[i] != CURL_SOCKET_BAD) {
          len = sizeof(readclient[i]) - tos[i];
          if(len && FD_ISSET(clientfd[i], &input)) {
            /* read from client */
            rc = sread(clientfd[i], &readclient[i][tos[i]], len);
            if(rc <= 0) {
              logmsg("[%s] got %zd, STOP READING client", data_or_ctrl(i), rc);
              shutdown(clientfd[i], SHUT_RD);
              poll_client_rd[i] = FALSE;
            }
            else {
              logmsg("[%s] READ %zd bytes from client", data_or_ctrl(i), rc);
              logmsg("[%s] READ \"%s\"", data_or_ctrl(i),
                     data_to_hex(&readclient[i][tos[i]], rc));
              tos[i] += rc;
            }
          }
        }
        if(serverfd[i] != CURL_SOCKET_BAD) {
          len = sizeof(readserver[i])-toc[i];
          if(len && FD_ISSET(serverfd[i], &input)) {
            /* read from server */
            rc = sread(serverfd[i], &readserver[i][toc[i]], len);
            if(rc <= 0) {
              logmsg("[%s] got %zd, STOP READING server", data_or_ctrl(i), rc);
              shutdown(serverfd[i], SHUT_RD);
              poll_server_rd[i] = FALSE;
            }
            else {
              logmsg("[%s] READ %zd bytes from server", data_or_ctrl(i), rc);
              logmsg("[%s] READ \"%s\"", data_or_ctrl(i),
                     data_to_hex(&readserver[i][toc[i]], rc));
              toc[i] += rc;
            }
          }
        }
        if(clientfd[i] != CURL_SOCKET_BAD) {
          if(toc[i] && FD_ISSET(clientfd[i], &output)) {
            /* write to client */
            rc = swrite(clientfd[i], readserver[i], toc[i]);
            if(rc <= 0) {
              logmsg("[%s] got %zd, STOP WRITING client", data_or_ctrl(i), rc);
              shutdown(clientfd[i], SHUT_WR);
              poll_client_wr[i] = FALSE;
              tcp_fin_wr = TRUE;
            }
            else {
              logmsg("[%s] SENT %zd bytes to client", data_or_ctrl(i), rc);
              logmsg("[%s] SENT \"%s\"", data_or_ctrl(i),
                     data_to_hex(readserver[i], rc));
              if(toc[i] - rc)
                memmove(&readserver[i][0], &readserver[i][rc], toc[i]-rc);
              toc[i] -= rc;
            }
          }
        }
        if(serverfd[i] != CURL_SOCKET_BAD) {
          if(tos[i] && FD_ISSET(serverfd[i], &output)) {
            /* write to server */
            rc = swrite(serverfd[i], readclient[i], tos[i]);
            if(rc <= 0) {
              logmsg("[%s] got %zd, STOP WRITING server", data_or_ctrl(i), rc);
              shutdown(serverfd[i], SHUT_WR);
              poll_server_wr[i] = FALSE;
              tcp_fin_wr = TRUE;
            }
            else {
              logmsg("[%s] SENT %zd bytes to server", data_or_ctrl(i), rc);
              logmsg("[%s] SENT \"%s\"", data_or_ctrl(i),
                     data_to_hex(readclient[i], rc));
              if(tos[i] - rc)
                memmove(&readclient[i][0], &readclient[i][rc], tos[i]-rc);
              tos[i] -= rc;
            }
          }
        }
      }
      if(got_exit_signal)
        break;

      /* ---------------------------------------------------------- */

      /* endpoint read/write disabling, endpoint closing and tunnel teardown */
      for(i = 0; i <= max_tunnel_idx; i++) {
        for(loop = 2; loop > 0; loop--) {
          /* loop twice to satisfy condition interdependencies without
             having to await select timeout or another socket event */
          if(clientfd[i] != CURL_SOCKET_BAD) {
            if(poll_client_rd[i] && !poll_server_wr[i]) {
              logmsg("[%s] DISABLED READING client", data_or_ctrl(i));
              shutdown(clientfd[i], SHUT_RD);
              poll_client_rd[i] = FALSE;
            }
            if(poll_client_wr[i] && !poll_server_rd[i] && !toc[i]) {
              logmsg("[%s] DISABLED WRITING client", data_or_ctrl(i));
              shutdown(clientfd[i], SHUT_WR);
              poll_client_wr[i] = FALSE;
              tcp_fin_wr = TRUE;
            }
          }
          if(serverfd[i] != CURL_SOCKET_BAD) {
            if(poll_server_rd[i] && !poll_client_wr[i]) {
              logmsg("[%s] DISABLED READING server", data_or_ctrl(i));
              shutdown(serverfd[i], SHUT_RD);
              poll_server_rd[i] = FALSE;
            }
            if(poll_server_wr[i] && !poll_client_rd[i] && !tos[i]) {
              logmsg("[%s] DISABLED WRITING server", data_or_ctrl(i));
              shutdown(serverfd[i], SHUT_WR);
              poll_server_wr[i] = FALSE;
              tcp_fin_wr = TRUE;
            }
          }
        }
      }

      if(tcp_fin_wr)
        /* allow kernel to place FIN bit packet on the wire */
        wait_ms(250);

      /* socket clearing */
      for(i = 0; i <= max_tunnel_idx; i++) {
        for(loop = 2; loop > 0; loop--) {
          if(clientfd[i] != CURL_SOCKET_BAD) {
            if(!poll_client_wr[i] && !poll_client_rd[i]) {
              logmsg("[%s] CLOSING client socket", data_or_ctrl(i));
              sclose(clientfd[i]);
              clientfd[i] = CURL_SOCKET_BAD;
              if(serverfd[i] == CURL_SOCKET_BAD) {
                logmsg("[%s] ENDING", data_or_ctrl(i));
                if(i == DATA)
                  secondary = FALSE;
                else
                  primary = FALSE;
              }
            }
          }
          if(serverfd[i] != CURL_SOCKET_BAD) {
            if(!poll_server_wr[i] && !poll_server_rd[i]) {
              logmsg("[%s] CLOSING server socket", data_or_ctrl(i));
              sclose(serverfd[i]);
              serverfd[i] = CURL_SOCKET_BAD;
              if(clientfd[i] == CURL_SOCKET_BAD) {
                logmsg("[%s] ENDING", data_or_ctrl(i));
                if(i == DATA)
                  secondary = FALSE;
                else
                  primary = FALSE;
              }
            }
          }
        }
      }

      /* ---------------------------------------------------------- */

      max_tunnel_idx = secondary ? DATA : CTRL;

      if(!primary)
        /* exit loop upon primary tunnel teardown */
        break;

    } /* (rc > 0) */
    else {
      timeout_count++;
      if(timeout_count > 5) {
        logmsg("CONNECT proxy timeout after %d idle seconds!", timeout_count);
        break;
      }
    }
  }

http_connect_cleanup:

  for(i = DATA; i >= CTRL; i--) {
    if(serverfd[i] != CURL_SOCKET_BAD) {
      logmsg("[%s] CLOSING server socket (cleanup)", data_or_ctrl(i));
      shutdown(serverfd[i], SHUT_RDWR);
      sclose(serverfd[i]);
    }
    if(clientfd[i] != CURL_SOCKET_BAD) {
      logmsg("[%s] CLOSING client socket (cleanup)", data_or_ctrl(i));
      shutdown(clientfd[i], SHUT_RDWR);
      sclose(clientfd[i]);
    }
    if((serverfd[i] != CURL_SOCKET_BAD) ||
       (clientfd[i] != CURL_SOCKET_BAD)) {
      logmsg("[%s] ABORTING", data_or_ctrl(i));
    }
  }

  *infdp = CURL_SOCKET_BAD;
}

static void http_upgrade(struct httprequest *req)
{
  (void)req;
  logmsg("Upgraded to ... %u", req->upgrade_request);
  /* left to implement */
}


/* returns a socket handle, or 0 if there are no more waiting sockets,
   or < 0 if there was an error */
static curl_socket_t accept_connection(curl_socket_t sock)
{
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int error;
  int flag = 1;

  if(MAX_SOCKETS == num_sockets) {
    logmsg("Too many open sockets!");
    return CURL_SOCKET_BAD;
  }

  msgsock = accept(sock, NULL, NULL);

  if(got_exit_signal) {
    if(CURL_SOCKET_BAD != msgsock)
      sclose(msgsock);
    return CURL_SOCKET_BAD;
  }

  if(CURL_SOCKET_BAD == msgsock) {
    error = SOCKERRNO;
    if(EAGAIN == error || EWOULDBLOCK == error) {
      /* nothing to accept */
      return 0;
    }
    logmsg("MAJOR ERROR: accept() failed with error: (%d) %s",
           error, strerror(error));
    return CURL_SOCKET_BAD;
  }

  if(0 != curlx_nonblock(msgsock, TRUE)) {
    error = SOCKERRNO;
    logmsg("curlx_nonblock failed with error: (%d) %s",
           error, strerror(error));
    sclose(msgsock);
    return CURL_SOCKET_BAD;
  }

  if(0 != setsockopt(msgsock, SOL_SOCKET, SO_KEEPALIVE,
                     (void *)&flag, sizeof(flag))) {
    error = SOCKERRNO;
    logmsg("setsockopt(SO_KEEPALIVE) failed with error: (%d) %s",
           error, strerror(error));
    sclose(msgsock);
    return CURL_SOCKET_BAD;
  }

  /*
  ** As soon as this server accepts a connection from the test harness it
  ** must set the server logs advisor read lock to indicate that server
  ** logs should not be read until this lock is removed by this server.
  */

  if(!serverlogslocked)
    set_advisor_read_lock(SERVERLOGS_LOCK);
  serverlogslocked += 1;

  logmsg("====> Client connect");

  all_sockets[num_sockets] = msgsock;
  num_sockets += 1;

#ifdef TCP_NODELAY
  if(socket_domain_is_ip()) {
    /*
     * Disable the Nagle algorithm to make it easier to send out a large
     * response in many small segments to torture the clients more.
     */
    if(0 != setsockopt(msgsock, IPPROTO_TCP, TCP_NODELAY,
                       (void *)&flag, sizeof(flag)))
      logmsg("====> TCP_NODELAY failed");
  }
#endif

  return msgsock;
}

/* returns 1 if the connection should be serviced again immediately, 0 if there
   is no data waiting, or < 0 if it should be closed */
static int service_connection(curl_socket_t msgsock, struct httprequest *req,
                              curl_socket_t listensock,
                              const char *connecthost)
{
  if(got_exit_signal)
    return -1;

  while(!req->done_processing) {
    int rc = get_request(msgsock, req);
    if(rc <= 0) {
      /* Nothing further to read now, possibly because the socket was closed */
      return rc;
    }
  }

  if(prevbounce) {
    /* bounce treatment requested */
    if((req->testno == prevtestno) &&
       (req->partno == prevpartno)) {
      req->partno++;
      logmsg("BOUNCE part number to %ld", req->partno);
    }
    else {
      prevbounce = FALSE;
      prevtestno = -1;
      prevpartno = -1;
    }
  }

  send_doc(msgsock, req);
  if(got_exit_signal)
    return -1;

  if(req->testno < 0) {
    logmsg("special request received, no persistency");
    return -1;
  }
  if(!req->open) {
    logmsg("instructed to close connection after server-reply");
    return -1;
  }

  if(req->connect_request) {
    /* a CONNECT request, setup and talk the tunnel */
    if(!is_proxy) {
      logmsg("received CONNECT but isn't running as proxy!");
      return 1;
    }
    else {
      http_connect(&msgsock, listensock, connecthost, req->connect_port);
      return -1;
    }
  }

  if(req->upgrade_request) {
    /* an upgrade request, switch to another protocol here */
    http_upgrade(req);
    return 1;
  }

  /* if we got a CONNECT, loop and get another request as well! */

  if(req->open) {
    logmsg("=> persistent connection request ended, awaits new request\n");
    return 1;
  }
  else {
    logmsg("=> NOT a persistent connection, close close CLOSE\n");
  }

  return -1;
}

int main(int argc, char *argv[])
{
  srvr_sockaddr_union_t me;
  curl_socket_t sock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  int wroteportfile = 0;
  int flag;
  unsigned short port = DEFAULT_PORT;
#ifdef USE_UNIX_SOCKETS
  const char *unix_socket = NULL;
  bool unlink_socket = false;
#endif
  const char *pidname = ".http.pid";
  const char *portname = ".http.port";
  struct httprequest *req = NULL;
  int rc = 0;
  int error;
  int arg = 1;
  const char *connecthost = "127.0.0.1";
  const char *socket_type = "IPv4";
  char port_str[11];
  const char *location_str = port_str;

  /* a default CONNECT port is basically pointless but still ... */
  size_t socket_idx;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      puts("sws IPv4"
#ifdef ENABLE_IPV6
             "/IPv6"
#endif
#ifdef USE_UNIX_SOCKETS
             "/unix"
#endif
          );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc>arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc>arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--cmdfile", argv[arg])) {
      arg++;
      if(argc>arg)
        cmdfile = argv[arg++];
    }
    else if(!strcmp("--gopher", argv[arg])) {
      arg++;
      use_gopher = TRUE;
      end_of_headers = "\r\n"; /* gopher style is much simpler */
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      socket_type = "IPv4";
      socket_domain = AF_INET;
      location_str = port_str;
      arg++;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef ENABLE_IPV6
      socket_type = "IPv6";
      socket_domain = AF_INET6;
      location_str = port_str;
#endif
      arg++;
    }
    else if(!strcmp("--unix-socket", argv[arg])) {
      arg++;
      if(argc>arg) {
#ifdef USE_UNIX_SOCKETS
        unix_socket = argv[arg];
        if(strlen(unix_socket) >= sizeof(me.sau.sun_path)) {
          fprintf(stderr, "sws: socket path must be shorter than %zu chars\n",
                  sizeof(me.sau.sun_path));
          return 0;
        }
        socket_type = "unix";
        socket_domain = AF_UNIX;
        location_str = unix_socket;
#endif
        arg++;
      }
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        if((endptr != argv[arg] + strlen(argv[arg])) ||
           (ulnum && ((ulnum < 1025UL) || (ulnum > 65535UL)))) {
          fprintf(stderr, "sws: invalid --port argument (%s)\n",
                  argv[arg]);
          return 0;
        }
        port = curlx_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--srcdir", argv[arg])) {
      arg++;
      if(argc>arg) {
        path = argv[arg];
        arg++;
      }
    }
    else if(!strcmp("--connect", argv[arg])) {
      /* The connect host IP number that the proxy will connect to no matter
         what the client asks for, but also use this as a hint that we run as
         a proxy and do a few different internal choices */
      arg++;
      if(argc>arg) {
        connecthost = argv[arg];
        arg++;
        is_proxy = TRUE;
        logmsg("Run as proxy, CONNECT to host %s", connecthost);
      }
    }
    else {
      puts("Usage: sws [option]\n"
           " --version\n"
           " --logfile [file]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --unix-socket [file]\n"
           " --port [port]\n"
           " --srcdir [path]\n"
           " --connect [ip4-addr]\n"
           " --gopher");
      return 0;
    }
  }

#ifdef WIN32
  win32_init();
  atexit(win32_cleanup);
#endif

  install_signal_handlers(false);

  req = calloc(1, sizeof(*req));
  if(!req)
    goto sws_cleanup;

  sock = socket(socket_domain, SOCK_STREAM, 0);

  all_sockets[0] = sock;
  num_sockets = 1;

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket: (%d) %s",
           error, strerror(error));
    goto sws_cleanup;
  }

  flag = 1;
  if(0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                     (void *)&flag, sizeof(flag))) {
    error = SOCKERRNO;
    logmsg("setsockopt(SO_REUSEADDR) failed with error: (%d) %s",
           error, strerror(error));
    goto sws_cleanup;
  }
  if(0 != curlx_nonblock(sock, TRUE)) {
    error = SOCKERRNO;
    logmsg("curlx_nonblock failed with error: (%d) %s",
           error, strerror(error));
    goto sws_cleanup;
  }

  switch(socket_domain) {
  case AF_INET:
    memset(&me.sa4, 0, sizeof(me.sa4));
    me.sa4.sin_family = AF_INET;
    me.sa4.sin_addr.s_addr = INADDR_ANY;
    me.sa4.sin_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa4));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    memset(&me.sa6, 0, sizeof(me.sa6));
    me.sa6.sin6_family = AF_INET6;
    me.sa6.sin6_addr = in6addr_any;
    me.sa6.sin6_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa6));
    break;
#endif /* ENABLE_IPV6 */
#ifdef USE_UNIX_SOCKETS
  case AF_UNIX:
    rc = bind_unix_socket(sock, unix_socket, &me.sau);
#endif /* USE_UNIX_SOCKETS */
  }
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket: (%d) %s", error, strerror(error));
    goto sws_cleanup;
  }

  if(!port) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef ENABLE_IPV6
    if(socket_domain != AF_INET6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef ENABLE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error: (%d) %s",
             error, strerror(error));
      sclose(sock);
      goto sws_cleanup;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      port = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      port = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!port) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      sclose(sock);
      goto sws_cleanup;
    }
  }
#ifdef USE_UNIX_SOCKETS
  if(socket_domain != AF_UNIX)
#endif
    msnprintf(port_str, sizeof(port_str), "port %hu", port);

  logmsg("Running %s %s version on %s",
         use_gopher?"GOPHER":"HTTP", socket_type, location_str);

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen() failed with error: (%d) %s",
           error, strerror(error));
    goto sws_cleanup;
  }

#ifdef USE_UNIX_SOCKETS
  /* listen succeeds, so let's assume a valid listening Unix socket */
  unlink_socket = true;
#endif

  /*
  ** As soon as this server writes its pid file the test harness will
  ** attempt to connect to this server and initiate its verification.
  */

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile)
    goto sws_cleanup;

  wroteportfile = write_portfile(portname, port);
  if(!wroteportfile)
    goto sws_cleanup;

  /* initialization of httprequest struct is done before get_request(), but
     the pipelining struct field must be initialized previously to FALSE
     every time a new connection arrives. */

  init_httprequest(req);

  for(;;) {
    fd_set input;
    fd_set output;
    struct timeval timeout = {0, 250000L}; /* 250 ms */
    curl_socket_t maxfd = (curl_socket_t)-1;
    int active;

    /* Clear out closed sockets */
    for(socket_idx = num_sockets - 1; socket_idx >= 1; --socket_idx) {
      if(CURL_SOCKET_BAD == all_sockets[socket_idx]) {
        char *dst = (char *) (all_sockets + socket_idx);
        char *src = (char *) (all_sockets + socket_idx + 1);
        char *end = (char *) (all_sockets + num_sockets);
        memmove(dst, src, end - src);
        num_sockets -= 1;
      }
    }

    if(got_exit_signal)
      goto sws_cleanup;

    /* Set up for select */
    FD_ZERO(&input);
    FD_ZERO(&output);

    for(socket_idx = 0; socket_idx < num_sockets; ++socket_idx) {
      /* Listen on all sockets */
      FD_SET(all_sockets[socket_idx], &input);
      if(all_sockets[socket_idx] > maxfd)
        maxfd = all_sockets[socket_idx];
    }

    if(got_exit_signal)
      goto sws_cleanup;

    do {
      rc = select((int)maxfd + 1, &input, &output, NULL, &timeout);
    } while(rc < 0 && errno == EINTR && !got_exit_signal);

    if(got_exit_signal)
      goto sws_cleanup;

    if(rc < 0) {
      error = SOCKERRNO;
      logmsg("select() failed with error: (%d) %s",
             error, strerror(error));
      goto sws_cleanup;
    }

    if(rc == 0) {
      /* Timed out - try again */
      continue;
    }
    active = rc; /* a positive number */

    /* Check if the listening socket is ready to accept */
    if(FD_ISSET(all_sockets[0], &input)) {
      /* Service all queued connections */
      curl_socket_t msgsock;
      do {
        msgsock = accept_connection(sock);
        logmsg("accept_connection %d returned %d", sock, msgsock);
        if(CURL_SOCKET_BAD == msgsock)
          goto sws_cleanup;
      } while(msgsock > 0);
      active--;
    }

    /* Service all connections that are ready */
    for(socket_idx = 1; (socket_idx < num_sockets) && active; ++socket_idx) {
      if(FD_ISSET(all_sockets[socket_idx], &input)) {
        active--;
        if(got_exit_signal)
          goto sws_cleanup;

        /* Service this connection until it has nothing available */
        do {
          rc = service_connection(all_sockets[socket_idx], req, sock,
                                  connecthost);
          if(got_exit_signal)
            goto sws_cleanup;

          if(rc < 0) {
            logmsg("====> Client disconnect %d", req->connmon);

            if(req->connmon) {
              const char *keepopen = "[DISCONNECT]\n";
              storerequest(keepopen, strlen(keepopen));
            }

            if(!req->open)
              /* When instructed to close connection after server-reply we
                 wait a very small amount of time before doing so. If this
                 is not done client might get an ECONNRESET before reading
                 a single byte of server-reply. */
              wait_ms(50);

            if(all_sockets[socket_idx] != CURL_SOCKET_BAD) {
              sclose(all_sockets[socket_idx]);
              all_sockets[socket_idx] = CURL_SOCKET_BAD;
            }

            serverlogslocked -= 1;
            if(!serverlogslocked)
              clear_advisor_read_lock(SERVERLOGS_LOCK);

            if(req->testno == DOCNUMBER_QUIT)
              goto sws_cleanup;
          }

          /* Reset the request, unless we're still in the middle of reading */
          if(rc && !req->upgrade_request)
            init_httprequest(req);
        } while(rc > 0);
      }
    }

    if(got_exit_signal)
      goto sws_cleanup;
  }

sws_cleanup:

  for(socket_idx = 1; socket_idx < num_sockets; ++socket_idx)
    if((all_sockets[socket_idx] != sock) &&
     (all_sockets[socket_idx] != CURL_SOCKET_BAD))
      sclose(all_sockets[socket_idx]);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

#ifdef USE_UNIX_SOCKETS
  if(unlink_socket && socket_domain == AF_UNIX) {
    rc = unlink(unix_socket);
    logmsg("unlink(%s) = %d (%s)", unix_socket, rc, strerror(rc));
  }
#endif

  free(req);

  if(got_exit_signal)
    logmsg("signalled to die");

  if(wrotepidfile)
    unlink(pidname);
  if(wroteportfile)
    unlink(portname);

  if(serverlogslocked) {
    serverlogslocked = 0;
    clear_advisor_read_lock(SERVERLOGS_LOCK);
  }

  restore_signal_handlers(false);

  if(got_exit_signal) {
    logmsg("========> %s sws (%s pid: %ld) exits with signal (%d)",
           socket_type, location_str, (long)getpid(), exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("========> sws quits");
  return 0;
}
