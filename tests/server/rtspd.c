/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * curl's test suite Real Time Streaming Protocol (RTSP) server.
 *
 * This source file was started based on curl's HTTP test suite server.
 */

#ifndef UNDER_CE
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

#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"
#include "server_sockaddr.h"

/* include memdebug.h last */
#include "memdebug.h"

#undef REQBUFSIZ
#define REQBUFSIZ 150000

static long rtspd_prevtestno = -1;    /* previous test number we served */
static long rtspd_prevpartno = -1;    /* previous part number we served */
static bool rtspd_prevbounce = FALSE; /* instructs the server to override the
                                         requested part number to
                                         prevpartno + 1 when prevtestno and
                                         current test are the same */

#define RCMD_NORMALREQ 0 /* default request, use the tests file normally */
#define RCMD_IDLE      1 /* told to sit idle */
#define RCMD_STREAM    2 /* told to stream */

typedef enum {
  RPROT_NONE = 0,
  RPROT_RTSP = 1,
  RPROT_HTTP = 2
} reqprot_t;

#define SET_RTP_PKT_CHN(p,c)  ((p)[1] = (char)((c) & 0xFF))

#define SET_RTP_PKT_LEN(p,l) (((p)[2] = (char)(((l) >> 8) & 0xFF)), \
                              ((p)[3] = (char)((l) & 0xFF)))

struct rtspd_httprequest {
  char reqbuf[REQBUFSIZ]; /* buffer area for the incoming request */
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
  bool ntlm;      /* Authorization NTLM header found */
  int pipe;       /* if non-zero, expect this many requests to do a "piped"
                     request/response */
  int skip;       /* if non-zero, the server is instructed to not read this
                     many bytes from a PUT/POST request. Ie the client sends N
                     bytes said in Content-Length, but the server only reads N
                     - skip bytes. */
  int rcmd;       /* doing a special command, see defines above */
  reqprot_t protocol; /* request protocol, HTTP or RTSP */
  int prot_version;   /* HTTP or RTSP version (major*10 + minor) */
  bool pipelining;    /* true if request is pipelined */
  char *rtp_buffer;
  size_t rtp_buffersize;
};

#define RTSPDVERSION "curl test suite RTSP server/0.1"

#define REQUEST_DUMP  "server.input"
#define RESPONSE_DUMP "server.response"

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

#define END_OF_HEADERS "\r\n\r\n"


/* sent as reply to a QUIT */
static const char *docquit_rtsp =
"HTTP/1.1 200 Goodbye" END_OF_HEADERS;

/* sent as reply to a CONNECT */
static const char *docconnect =
"HTTP/1.1 200 Mighty fine indeed" END_OF_HEADERS;

/* sent as reply to a "bad" CONNECT */
static const char *docbadconnect =
"HTTP/1.1 501 Forbidden you fool" END_OF_HEADERS;

/* send back this on HTTP 404 file not found */
static const char *doc404_HTTP = "HTTP/1.1 404 Not Found\r\n"
    "Server: " RTSPDVERSION "\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html"
    END_OF_HEADERS
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<HTML><HEAD>\n"
    "<TITLE>404 Not Found</TITLE>\n"
    "</HEAD><BODY>\n"
    "<H1>Not Found</H1>\n"
    "The requested URL was not found on this server.\n"
    "<P><HR><ADDRESS>" RTSPDVERSION "</ADDRESS>\n" "</BODY></HTML>\n";

/* send back this on RTSP 404 file not found */
static const char *doc404_RTSP = "RTSP/1.0 404 Not Found\r\n"
    "Server: " RTSPDVERSION
    END_OF_HEADERS;

/* Default size to send away fake RTP data */
#define RTP_DATA_SIZE 12
static const char *RTP_DATA = "$_1234\n\0Rsdf";

static int rtspd_ProcessRequest(struct rtspd_httprequest *req)
{
  char *line = &req->reqbuf[req->checkindex];
  bool chunked = FALSE;
  static char request[REQUEST_KEYWORD_SIZE];
  static char doc[MAXDOCNAMELEN];
  static char prot_str[5];
  int prot_major, prot_minor;
  char *end = strstr(line, END_OF_HEADERS);

  logmsg("rtspd_ProcessRequest() called with testno %ld and line [%s]",
         req->testno, line);

  /* try to figure out the request characteristics as soon as possible, but
     only once! */
  if((req->testno == DOCNUMBER_NOTHING) &&
     sscanf(line,
            "%" REQUEST_KEYWORD_SIZE_TXT"s %" MAXDOCNAMELEN_TXT "s %4s/%d.%d",
            request,
            doc,
            prot_str,
            &prot_major,
            &prot_minor) == 5) {
    char *ptr;
    char logbuf[256];

    if(!strcmp(prot_str, "HTTP")) {
      req->protocol = RPROT_HTTP;
    }
    else if(!strcmp(prot_str, "RTSP")) {
      req->protocol = RPROT_RTSP;
    }
    else {
      req->protocol = RPROT_NONE;
      logmsg("got unknown protocol %s", prot_str);
      return 1;
    }

    req->prot_version = prot_major*10 + prot_minor;

    /* find the last slash */
    ptr = strrchr(doc, '/');

    /* get the number after it */
    if(ptr) {
      FILE *stream;
      if((strlen(doc) + strlen(request)) < 200)
        msnprintf(logbuf, sizeof(logbuf), "Got request: %s %s %s/%d.%d",
                  request, doc, prot_str, prot_major, prot_minor);
      else
        msnprintf(logbuf, sizeof(logbuf), "Got a *HUGE* request %s/%d.%d",
                  prot_str, prot_major, prot_minor);
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

      msnprintf(logbuf, sizeof(logbuf), "Requested test number %ld part %ld",
                req->testno, req->partno);
      logmsg("%s", logbuf);

      stream = test2fopen(req->testno, logdir);

      if(!stream) {
        int error = errno;
        logmsg("fopen() failed with error (%d) %s", error, strerror(error));
        logmsg("Couldn't open test file %ld", req->testno);
        req->open = FALSE; /* closes connection */
        return 1; /* done */
      }
      else {
        char *cmd = NULL;
        size_t cmdsize = 0;
        int num = 0;

        int rtp_channel = 0;
        int rtp_size = 0;
        int rtp_size_err = 0;
        int rtp_partno = -1;
        char *rtp_scratch = NULL;

        /* get the custom server control "commands" */
        int error = getpart(&cmd, &cmdsize, "reply", "servercmd", stream);
        fclose(stream);
        if(error) {
          logmsg("getpart() failed with error (%d)", error);
          req->open = FALSE; /* closes connection */
          return 1; /* done */
        }
        ptr = cmd;

        if(cmdsize) {
          logmsg("Found a reply-servercmd section!");
          do {
            rtp_size_err = 0;
            if(!strncmp(CMD_AUTH_REQUIRED, ptr, strlen(CMD_AUTH_REQUIRED))) {
              logmsg("instructed to require authorization header");
              req->auth_req = TRUE;
            }
            else if(!strncmp(CMD_IDLE, ptr, strlen(CMD_IDLE))) {
              logmsg("instructed to idle");
              req->rcmd = RCMD_IDLE;
              req->open = TRUE;
            }
            else if(!strncmp(CMD_STREAM, ptr, strlen(CMD_STREAM))) {
              logmsg("instructed to stream");
              req->rcmd = RCMD_STREAM;
            }
            else if(1 == sscanf(ptr, "pipe: %d", &num)) {
              logmsg("instructed to allow a pipe size of %d", num);
              if(num < 0)
                logmsg("negative pipe size ignored");
              else if(num > 0)
                req->pipe = num-1; /* decrease by one since we don't count the
                                      first request in this number */
            }
            else if(1 == sscanf(ptr, "skip: %d", &num)) {
              logmsg("instructed to skip this number of bytes %d", num);
              req->skip = num;
            }
            else if(3 <= sscanf(ptr,
                                "rtp: part %d channel %d size %d size_err %d",
                                &rtp_partno, &rtp_channel, &rtp_size,
                                &rtp_size_err)) {

              if(rtp_partno == req->partno) {
                int i = 0;
                logmsg("RTP: part %d channel %d size %d size_err %d",
                       rtp_partno, rtp_channel, rtp_size, rtp_size_err);

                /* Make our scratch buffer enough to fit all the
                 * desired data and one for padding */
                rtp_scratch = malloc(rtp_size + 4 + RTP_DATA_SIZE);

                /* RTP is signalled with a $ */
                rtp_scratch[0] = '$';

                /* The channel follows and is one byte */
                SET_RTP_PKT_CHN(rtp_scratch, rtp_channel);

                /* Length follows and is a two byte short in network order */
                SET_RTP_PKT_LEN(rtp_scratch, rtp_size + rtp_size_err);

                /* Fill it with junk data */
                for(i = 0; i < rtp_size; i += RTP_DATA_SIZE) {
                  memcpy(rtp_scratch + 4 + i, RTP_DATA, RTP_DATA_SIZE);
                }

                if(!req->rtp_buffer) {
                  req->rtp_buffer = rtp_scratch;
                  req->rtp_buffersize = rtp_size + 4;
                }
                else {
                  req->rtp_buffer = realloc(req->rtp_buffer,
                                            req->rtp_buffersize +
                                            rtp_size + 4);
                  memcpy(req->rtp_buffer + req->rtp_buffersize, rtp_scratch,
                         rtp_size + 4);
                  req->rtp_buffersize += rtp_size + 4;
                  free(rtp_scratch);
                }
                logmsg("rtp_buffersize is %zu, rtp_size is %d.",
                       req->rtp_buffersize, rtp_size);
              }
            }
            else {
              logmsg("funny instruction found: %s", ptr);
            }

            ptr = strchr(ptr, '\n');
            if(ptr)
              ptr++;
            else
              ptr = NULL;
          } while(ptr && *ptr);
          logmsg("Done parsing server commands");
        }
        free(cmd);
      }
    }
    else {
      if(sscanf(req->reqbuf, "CONNECT %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
                doc, &prot_major, &prot_minor) == 3) {
        msnprintf(logbuf, sizeof(logbuf),
                  "Received a CONNECT %s HTTP/%d.%d request",
                  doc, prot_major, prot_minor);
        logmsg("%s", logbuf);

        if(req->prot_version == 10)
          req->open = FALSE; /* HTTP 1.0 closes connection by default */

        if(!strncmp(doc, "bad", 3))
          /* if the host name starts with bad, we fake an error here */
          req->testno = DOCNUMBER_BADCONNECT;
        else if(!strncmp(doc, "test", 4)) {
          /* if the host name starts with test, the port number used in the
             CONNECT line will be used as test number! */
          char *portp = strchr(doc, ':');
          if(portp && (*(portp + 1) != '\0') && ISDIGIT(*(portp + 1)))
            req->testno = strtol(portp + 1, NULL, 10);
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

  if(!end) {
    /* we don't have a complete request yet! */
    logmsg("rtspd_ProcessRequest returned without a complete request");
    return 0; /* not complete yet */
  }
  logmsg("rtspd_ProcessRequest found a complete request");

  if(req->pipe)
    /* we do have a full set, advance the checkindex to after the end of the
       headers, for the pipelining case mostly */
    req->checkindex += (end - line) + strlen(END_OF_HEADERS);

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
      curl_off_t clen;
      const char *p = line + strlen("Content-Length:");
      if(curlx_str_numblanks(&p, &clen)) {
        /* this assumes that a zero Content-Length is valid */
        logmsg("Found invalid '%s' in the request", line);
        req->open = FALSE; /* closes connection */
        return 1; /* done */
      }
      req->cl = (size_t)clen - req->skip;

      logmsg("Found Content-Length: %zu in the request", (size_t)clen);
      if(req->skip)
        logmsg("... but will abort after %zu bytes", req->cl);
      break;
    }
    else if(strncasecompare("Transfer-Encoding: chunked", line,
                            strlen("Transfer-Encoding: chunked"))) {
      /* chunked data coming in */
      chunked = TRUE;
    }

    if(chunked) {
      if(strstr(req->reqbuf, "\r\n0\r\n\r\n"))
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

  if(!req->pipe &&
     req->open &&
     req->prot_version >= 11 &&
     req->reqbuf + req->offset > end + strlen(END_OF_HEADERS) &&
     (!strncmp(req->reqbuf, "GET", strlen("GET")) ||
      !strncmp(req->reqbuf, "HEAD", strlen("HEAD")))) {
    /* If we have a persistent connection, HTTP version >= 1.1
       and GET/HEAD request, enable pipelining. */
    req->checkindex = (end - req->reqbuf) + strlen(END_OF_HEADERS);
    req->pipelining = TRUE;
  }

  while(req->pipe) {
    if(got_exit_signal)
      return 1; /* done */
    /* scan for more header ends within this chunk */
    line = &req->reqbuf[req->checkindex];
    end = strstr(line, END_OF_HEADERS);
    if(!end)
      break;
    req->checkindex += (end - line) + strlen(END_OF_HEADERS);
    req->pipe--;
  }

  /* If authentication is required and no auth was provided, end now. This
     makes the server NOT wait for PUT/POST data and you can then make the
     test case send a rejection before any such data has been sent. Test case
     154 uses this.*/
  if(req->auth_req && !req->auth)
    return 1; /* done */

  if(req->cl > 0) {
    if(req->cl <= req->offset - (end - req->reqbuf) - strlen(END_OF_HEADERS))
      return 1; /* done */
    else
      return 0; /* not complete yet */
  }

  return 1; /* done */
}

/* store the entire request in a file */
static void rtspd_storerequest(char *reqbuf, size_t totalsize)
{
  int res;
  int error = 0;
  size_t written;
  size_t writeleft;
  FILE *dump;
  char dumpfile[256];

  msnprintf(dumpfile, sizeof(dumpfile), "%s/%s", logdir, REQUEST_DUMP);

  if(!reqbuf)
    return;
  if(totalsize == 0)
    return;

  do {
    dump = fopen(dumpfile, "ab");
    /* !checksrc! disable ERRNOVAR 1 */
  } while(!dump && ((error = errno) == EINTR));
  if(!dump) {
    logmsg("Error opening file %s error (%d) %s",
           dumpfile, error, strerror(error));
    logmsg("Failed to write request input to %s", dumpfile);
    return;
  }

  writeleft = totalsize;
  do {
    written = fwrite(&reqbuf[totalsize-writeleft], 1, writeleft, dump);
    if(got_exit_signal)
      goto storerequest_cleanup;
    if(written > 0)
      writeleft -= written;
    error = errno;
    /* !checksrc! disable ERRNOVAR 1 */
  } while((writeleft > 0) && (error == EINTR));

  if(writeleft == 0)
    logmsg("Wrote request (%zu bytes) input to %s", totalsize, dumpfile);
  else if(writeleft > 0) {
    logmsg("Error writing file %s error (%d) %s",
           dumpfile, error, strerror(error));
    logmsg("Wrote only (%zu bytes) of (%zu bytes) request input to %s",
           totalsize-writeleft, totalsize, dumpfile);
  }

storerequest_cleanup:

  res = fclose(dump);
  if(res)
    logmsg("Error closing file %s error (%d) %s",
           dumpfile, errno, strerror(errno));
}

/* return 0 on success, non-zero on failure */
static int rtspd_get_request(curl_socket_t sock, struct rtspd_httprequest *req)
{
  int error;
  int fail = 0;
  int done_processing = 0;
  char *reqbuf = req->reqbuf;
  ssize_t got = 0;

  char *pipereq = NULL;
  size_t pipereq_length = 0;

  if(req->pipelining) {
    pipereq = reqbuf + req->checkindex;
    pipereq_length = req->offset - req->checkindex;
  }

  /*** Init the httprequest structure properly for the upcoming request ***/

  req->checkindex = 0;
  req->offset = 0;
  req->testno = DOCNUMBER_NOTHING;
  req->partno = 0;
  req->open = TRUE;
  req->auth_req = FALSE;
  req->auth = FALSE;
  req->cl = 0;
  req->digest = FALSE;
  req->ntlm = FALSE;
  req->pipe = 0;
  req->skip = 0;
  req->rcmd = RCMD_NORMALREQ;
  req->protocol = RPROT_NONE;
  req->prot_version = 0;
  req->pipelining = FALSE;
  req->rtp_buffer = NULL;
  req->rtp_buffersize = 0;

  /*** end of httprequest init ***/

  while(!done_processing && (req->offset < REQBUFSIZ-1)) {
    if(pipereq_length && pipereq) {
      memmove(reqbuf, pipereq, pipereq_length);
      got = curlx_uztosz(pipereq_length);
      pipereq_length = 0;
    }
    else {
      if(req->skip)
        /* we are instructed to not read the entire thing, so we make sure to
           only read what we're supposed to and NOT read the enire thing the
           client wants to send! */
        got = sread(sock, reqbuf + req->offset, req->cl);
      else
        got = sread(sock, reqbuf + req->offset, REQBUFSIZ-1 - req->offset);
    }
    if(got_exit_signal)
      return 1;
    if(got == 0) {
      logmsg("Connection closed by client");
      fail = 1;
    }
    else if(got < 0) {
      error = SOCKERRNO;
      logmsg("recv() returned error (%d) %s", error, sstrerror(error));
      fail = 1;
    }
    if(fail) {
      /* dump the request received so far to the external file */
      reqbuf[req->offset] = '\0';
      rtspd_storerequest(reqbuf, req->offset);
      return 1;
    }

    logmsg("Read %zd bytes", got);

    req->offset += (size_t)got;
    reqbuf[req->offset] = '\0';

    done_processing = rtspd_ProcessRequest(req);
    if(got_exit_signal)
      return 1;
    if(done_processing && req->pipe) {
      logmsg("Waiting for another piped request");
      done_processing = 0;
      req->pipe--;
    }
  }

  if((req->offset == REQBUFSIZ-1) && (got > 0)) {
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

  /* dump the request to an external file */
  rtspd_storerequest(reqbuf, req->pipelining ? req->checkindex : req->offset);
  if(got_exit_signal)
    return 1;

  return fail; /* return 0 on success */
}

/* returns -1 on failure */
static int rtspd_send_doc(curl_socket_t sock, struct rtspd_httprequest *req)
{
  ssize_t written;
  size_t count;
  const char *buffer;
  char *ptr = NULL;
  char *cmd = NULL;
  size_t cmdsize = 0;
  FILE *dump;
  bool persistent = TRUE;
  bool sendfailure = FALSE;
  size_t responsesize;
  int error = 0;
  int res;
  static char weare[256];
  char responsedump[256];

  msnprintf(responsedump, sizeof(responsedump), "%s/%s",
            logdir, RESPONSE_DUMP);

  logmsg("Send response number %ld part %ld", req->testno, req->partno);

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
      buffer = docquit_rtsp;
      break;
    case DOCNUMBER_WERULEZ:
      /* we got a "friends?" question, reply back that we sure are */
      logmsg("Identifying ourselves as friends");
      msnprintf(msgbuf, sizeof(msgbuf), "RTSP_SERVER WE ROOLZ: %"
                CURL_FORMAT_CURL_OFF_T "\r\n", our_getpid());
      msglen = strlen(msgbuf);
      msnprintf(weare, sizeof(weare),
                "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s",
                msglen, msgbuf);
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
      if(req->protocol == RPROT_HTTP) {
        buffer = doc404_HTTP;
      }
      else {
        buffer = doc404_RTSP;
      }
      break;
    }

    count = strlen(buffer);
  }
  else {
    FILE *stream = test2fopen(req->testno, logdir);
    char partbuf[80]="data";
    if(0 != req->partno)
      msnprintf(partbuf, sizeof(partbuf), "data%ld", req->partno);
    if(!stream) {
      error = errno;
      logmsg("fopen() failed with error (%d) %s", error, strerror(error));
      logmsg("Couldn't open test file");
      return 0;
    }
    else {
      error = getpart(&ptr, &count, "reply", partbuf, stream);
      fclose(stream);
      if(error) {
        logmsg("getpart() failed with error (%d)", error);
        return 0;
      }
      buffer = ptr;
    }

    if(got_exit_signal) {
      free(ptr);
      return -1;
    }

    /* re-open the same file again */
    stream = test2fopen(req->testno, logdir);
    if(!stream) {
      error = errno;
      logmsg("fopen() failed with error (%d) %s", error, strerror(error));
      logmsg("Couldn't open test file");
      free(ptr);
      return 0;
    }
    else {
      /* get the custom server control "commands" */
      error = getpart(&cmd, &cmdsize, "reply", "postcmd", stream);
      fclose(stream);
      if(error) {
        logmsg("getpart() failed with error (%d)", error);
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
  if(strstr(buffer, "swsclose") || !count) {
    persistent = FALSE;
    logmsg("connection close instruction \"swsclose\" found in response");
  }
  if(strstr(buffer, "swsbounce")) {
    rtspd_prevbounce = TRUE;
    logmsg("enable \"swsbounce\" in the next request");
  }
  else
    rtspd_prevbounce = FALSE;

  dump = fopen(responsedump, "ab");
  if(!dump) {
    error = errno;
    logmsg("fopen() failed with error (%d) %s", error, strerror(error));
    logmsg("Error opening file '%s'", responsedump);
    logmsg("couldn't create logfile '%s'", responsedump);
    free(ptr);
    free(cmd);
    return -1;
  }

  responsesize = count;
  do {
    /* Ok, we send no more than 200 bytes at a time, just to make sure that
       larger chunks are split up so that the client will need to do multiple
       recv() calls to get it and thus we exercise that code better */
    size_t num = count;
    if(num > 200)
      num = 200;
    written = swrite(sock, buffer, num);
    if(written < 0) {
      sendfailure = TRUE;
      break;
    }
    else {
      logmsg("Sent off %zd bytes", written);
    }
    /* write to file as well */
    fwrite(buffer, 1, (size_t)written, dump);
    if(got_exit_signal)
      break;

    count -= written;
    buffer += written;
  } while(count > 0);

  /* Send out any RTP data */
  if(req->rtp_buffer) {
    logmsg("About to write %zu RTP bytes", req->rtp_buffersize);
    count = req->rtp_buffersize;
    do {
      size_t num = count;
      if(num > 200)
        num = 200;
      written = swrite(sock, req->rtp_buffer + (req->rtp_buffersize - count),
                       num);
      if(written < 0) {
        sendfailure = TRUE;
        break;
      }
      count -= written;
    } while(count > 0);

    free(req->rtp_buffer);
    req->rtp_buffersize = 0;
  }

  res = fclose(dump);
  if(res)
    logmsg("Error closing file %s error (%d) %s",
           responsedump, errno, strerror(errno));

  if(got_exit_signal) {
    free(ptr);
    free(cmd);
    return -1;
  }

  if(sendfailure) {
    logmsg("Sending response failed. Only (%zu bytes) of "
           "(%zu bytes) were sent",
           responsesize-count, responsesize);
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
          while(quarters > 0) {
            quarters--;
            res = wait_ms(250);
            if(got_exit_signal)
              break;
            if(res) {
              /* should not happen */
              error = SOCKERRNO;
              logmsg("wait_ms() failed with error (%d) %s",
                     error, sstrerror(error));
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
  req->open = persistent;

  rtspd_prevtestno = req->testno;
  rtspd_prevpartno = req->partno;

  return 0;
}


int main(int argc, char *argv[])
{
  srvr_sockaddr_union_t me;
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  int wroteportfile = 0;
  int flag;
  unsigned short port = 8999;
  struct rtspd_httprequest req;
  int rc;
  int error;
  int arg = 1;

  memset(&req, 0, sizeof(req));

  pidname = ".rtsp.pid";
  serverlogfile = "log/rtspd.log";
  serverlogslocked = 0;

  while(argc > arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("rtspd IPv4%s"
             "\n"
             ,
#ifdef USE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc > arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc > arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc > arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--logdir", argv[arg])) {
      arg++;
      if(argc > arg)
        logdir = argv[arg++];
    }
    else if(!strcmp("--ipv4", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc > arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        port = util_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--srcdir", argv[arg])) {
      arg++;
      if(argc > arg) {
        srcpath = argv[arg];
        arg++;
      }
    }
    else {
      puts("Usage: rtspd [option]\n"
           " --version\n"
           " --logfile [file]\n"
           " --logdir [directory]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --port [port]\n"
           " --srcdir [path]");
      return 0;
    }
  }

  msnprintf(loglockfile, sizeof(loglockfile), "%s/%s/rtsp-%s.lock",
            logdir, SERVERLOGS_LOCKDIR, ipv_inuse);

#ifdef _WIN32
  if(win32_init())
    return 2;
#endif

  install_signal_handlers(false);

#ifdef USE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef USE_IPV6
  else
    sock = socket(AF_INET6, SOCK_STREAM, 0);
#endif

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket (%d) %s", error, sstrerror(error));
    goto server_cleanup;
  }

  flag = 1;
  if(0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
            (void *)&flag, sizeof(flag))) {
    error = SOCKERRNO;
    logmsg("setsockopt(SO_REUSEADDR) failed with error (%d) %s",
           error, sstrerror(error));
    goto server_cleanup;
  }

#ifdef USE_IPV6
  if(!use_ipv6) {
#endif
    memset(&me.sa4, 0, sizeof(me.sa4));
    me.sa4.sin_family = AF_INET;
    me.sa4.sin_addr.s_addr = INADDR_ANY;
    me.sa4.sin_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa4));
#ifdef USE_IPV6
  }
  else {
    memset(&me.sa6, 0, sizeof(me.sa6));
    me.sa6.sin6_family = AF_INET6;
    me.sa6.sin6_addr = in6addr_any;
    me.sa6.sin6_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa6));
  }
#endif /* USE_IPV6 */
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu (%d) %s",
           port, error, sstrerror(error));
    goto server_cleanup;
  }

  if(!port) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef USE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error (%d) %s",
             error, sstrerror(error));
      sclose(sock);
      goto server_cleanup;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      port = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef USE_IPV6
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
      goto server_cleanup;
    }
  }
  logmsg("Running %s version on port %d", ipv_inuse, (int)port);

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen() failed with error (%d) %s",
           error, sstrerror(error));
    goto server_cleanup;
  }

  /*
  ** As soon as this server writes its pid file the test harness will
  ** attempt to connect to this server and initiate its verification.
  */

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile)
    goto server_cleanup;

  if(portname) {
    wroteportfile = write_portfile(portname, port);
    if(!wroteportfile)
      goto server_cleanup;
  }

  for(;;) {
    msgsock = accept(sock, NULL, NULL);

    if(got_exit_signal)
      break;
    if(CURL_SOCKET_BAD == msgsock) {
      error = SOCKERRNO;
      logmsg("MAJOR ERROR, accept() failed with error (%d) %s",
             error, sstrerror(error));
      break;
    }

    /*
    ** As soon as this server accepts a connection from the test harness it
    ** must set the server logs advisor read lock to indicate that server
    ** logs should not be read until this lock is removed by this server.
    */

    set_advisor_read_lock(loglockfile);
    serverlogslocked = 1;

    logmsg("====> Client connect");

#ifdef TCP_NODELAY
    /*
     * Disable the Nagle algorithm to make it easier to send out a large
     * response in many small segments to torture the clients more.
     */
    flag = 1;
    if(setsockopt(msgsock, IPPROTO_TCP, TCP_NODELAY,
                   (void *)&flag, sizeof(flag)) == -1) {
      logmsg("====> TCP_NODELAY failed");
    }
#endif

    /* initialization of httprequest struct is done in rtspd_get_request(),
       but due to pipelining treatment the pipelining struct field must be
       initialized previously to FALSE every time a new connection arrives. */

    req.pipelining = FALSE;

    do {
      if(got_exit_signal)
        break;

      if(rtspd_get_request(msgsock, &req))
        /* non-zero means error, break out of loop */
        break;

      if(rtspd_prevbounce) {
        /* bounce treatment requested */
        if(req.testno == rtspd_prevtestno) {
          req.partno = rtspd_prevpartno + 1;
          logmsg("BOUNCE part number to %ld", req.partno);
        }
        else {
          rtspd_prevbounce = FALSE;
          rtspd_prevtestno = -1;
          rtspd_prevpartno = -1;
        }
      }

      rtspd_send_doc(msgsock, &req);
      if(got_exit_signal)
        break;

      if((req.testno < 0) && (req.testno != DOCNUMBER_CONNECT)) {
        logmsg("special request received, no persistency");
        break;
      }
      if(!req.open) {
        logmsg("instructed to close connection after server-reply");
        break;
      }

      if(req.open)
        logmsg("=> persistent connection request ended, awaits new request");
      /* if we got a CONNECT, loop and get another request as well! */
    } while(req.open || (req.testno == DOCNUMBER_CONNECT));

    if(got_exit_signal)
      break;

    logmsg("====> Client disconnect");
    sclose(msgsock);
    msgsock = CURL_SOCKET_BAD;

    if(serverlogslocked) {
      serverlogslocked = 0;
      clear_advisor_read_lock(loglockfile);
    }

    if(req.testno == DOCNUMBER_QUIT)
      break;
  }

server_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(got_exit_signal)
    logmsg("signalled to die");

  if(wrotepidfile)
    unlink(pidname);
  if(wroteportfile)
    unlink(portname);

  if(serverlogslocked) {
    serverlogslocked = 0;
    clear_advisor_read_lock(loglockfile);
  }

  restore_signal_handlers(false);

  if(got_exit_signal) {
    logmsg("========> %s rtspd (port: %d pid: %ld) exits with signal (%d)",
           ipv_inuse, (int)port, (long)curlx_getpid(), exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("========> rtspd quits");
  return 0;
}
