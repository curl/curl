/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#ifndef CURL_DISABLE_FTP
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)

#else /* probably some kind of unix */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef  VMS
#include <in.h>
#include <inet.h>
#endif
#endif

#if defined(WIN32) && defined(__GNUC__) || defined(__MINGW32__)
#include <errno.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"

#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "ftp.h"

#ifdef HAVE_KRB4
#include "krb4.h"
#endif

#include "strtoofft.h"
#include "strequal.h"
#include "ssluse.h"
#include "connect.h"
#include "strerror.h"
#include "memory.h"
#include "inet_ntop.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

#ifdef HAVE_NI_WITHSCOPEID
#define NIFLAGS NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID
#else
#define NIFLAGS NI_NUMERICHOST | NI_NUMERICSERV
#endif

/* Local API functions */
static CURLcode ftp_sendquote(struct connectdata *conn,
                              struct curl_slist *quote);
static CURLcode ftp_cwd(struct connectdata *conn, char *path);
static CURLcode ftp_mkd(struct connectdata *conn, char *path);
static CURLcode ftp_cwd_and_mkd(struct connectdata *conn, char *path);
static CURLcode ftp_quit(struct connectdata *conn);
static CURLcode ftp_3rdparty_pretransfer(struct connectdata *conn);
static CURLcode ftp_3rdparty_transfer(struct connectdata *conn);
static CURLcode ftp_parse_url_path(struct connectdata *conn);
static CURLcode ftp_cwd_and_create_path(struct connectdata *conn);
static CURLcode ftp_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode ftp_3rdparty(struct connectdata *conn);
static void ftp_pasv_verbose(struct connectdata *conn,
                             Curl_addrinfo *ai,
                             char *newhost, /* ascii version */
                             int port);
static CURLcode ftp_state_post_rest(struct connectdata *conn);
static CURLcode ftp_state_post_cwd(struct connectdata *conn);
static CURLcode ftp_state_quote(struct connectdata *conn,
                                bool init, ftpstate instate);

/* easy-to-use macro: */
#define FTPSENDF(x,y,z) if((result = Curl_ftpsendf(x,y,z))) return result
#define NBFTPSENDF(x,y,z) if((result = Curl_nbftpsendf(x,y,z))) return result

static void freedirs(struct FTP *ftp)
{
  int i;
  if(ftp->dirs) {
    for (i=0; i < ftp->dirdepth; i++){
      if(ftp->dirs[i]) {
        free(ftp->dirs[i]);
        ftp->dirs[i]=NULL;
      }
    }
    free(ftp->dirs);
    ftp->dirs = NULL;
  }
  if(ftp->file) {
    free(ftp->file);
    ftp->file = NULL;
  }
}

/* Returns non-zero iff the given string contains CR (0x0D) or LF (0x0A), which
   are not allowed within RFC 959 <string>.
 */
static bool isBadFtpString(const char *string)
{
  return strchr(string, 0x0D) != NULL || strchr(string, 0x0A) != NULL;
}

/***********************************************************************
 *
 * AllowServerConnect()
 *
 * When we've issue the PORT command, we have told the server to connect
 * to us. This function will sit and wait here until the server has
 * connected.
 *
 */
static CURLcode AllowServerConnect(struct connectdata *conn)
{
  int timeout_ms;
  struct SessionHandle *data = conn->data;
  curl_socket_t sock = conn->sock[SECONDARYSOCKET];
  struct timeval now = Curl_tvnow();
  long timespent = Curl_tvdiff(Curl_tvnow(), now)/1000;
  long timeout = data->set.connecttimeout?data->set.connecttimeout:
    (data->set.timeout?data->set.timeout: 0);

  if(timeout) {
    timeout -= timespent;
    if(timeout<=0) {
      failf(data, "Timed out before server could connect to us");
      return CURLE_OPERATION_TIMEDOUT;
    }
  }

  /* We allow the server 60 seconds to connect to us, or a custom timeout.
     Note the typecast here. */
  timeout_ms = (timeout?(int)timeout:60) * 1000;

  switch (Curl_select(sock, CURL_SOCKET_BAD, timeout_ms)) {
  case -1: /* error */
    /* let's die here */
    failf(data, "Error while waiting for server connect");
    return CURLE_FTP_PORT_FAILED;
  case 0:  /* timeout */
    /* let's die here */
    failf(data, "Timeout while waiting for server connect");
    return CURLE_FTP_PORT_FAILED;
  default:
    /* we have received data here */
    {
      curl_socket_t s;
      size_t size = sizeof(struct sockaddr_in);
      struct sockaddr_in add;

      getsockname(sock, (struct sockaddr *) &add, (socklen_t *)&size);
      s=accept(sock, (struct sockaddr *) &add, (socklen_t *)&size);

      sclose(sock); /* close the first socket */

      if (CURL_SOCKET_BAD == s) {
        /* DIE! */
        failf(data, "Error accept()ing server connect");
        return CURLE_FTP_PORT_FAILED;
      }
      infof(data, "Connection accepted from server\n");

      conn->sock[SECONDARYSOCKET] = s;
      Curl_nonblock(s, TRUE); /* enable non-blocking */
    }
    break;
  }

  return CURLE_OK;
}


static CURLcode ftp_readresp(curl_socket_t sockfd,
                             struct connectdata *conn,
                             int *ftpcode, /* return the ftp-code if done */
                             size_t *size) /* size of the response */
{
  int perline; /* count bytes per line */
  bool keepon=TRUE;
  ssize_t gotbytes;
  char *ptr;
  struct SessionHandle *data = conn->data;
  char *line_start;
  char *buf = data->state.buffer;
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  int code = 0;

  if (ftpcode)
    *ftpcode = 0; /* 0 for errors or not done */

  ptr=buf;
  line_start = buf;

  perline=0;
  keepon=TRUE;

  while((ftp->nread_resp<BUFSIZE) && (keepon && !result)) {

    if(ftp->cache) {
      /* we had data in the "cache", copy that instead of doing an actual
       * read
       *
       * ftp->cache_size is cast to int here.  This should be safe,
       * because it would have been populated with something of size
       * int to begin with, even though its datatype may be larger
       * than an int.
       */
      memcpy(ptr, ftp->cache, (int)ftp->cache_size);
      gotbytes = (int)ftp->cache_size;
      free(ftp->cache);    /* free the cache */
      ftp->cache = NULL;   /* clear the pointer */
      ftp->cache_size = 0; /* zero the size just in case */
    }
    else {
      int res = Curl_read(conn, sockfd, ptr, BUFSIZE-ftp->nread_resp,
                          &gotbytes);
      if(res < 0)
        /* EWOULDBLOCK */
        return CURLE_OK; /* return */

      if(CURLE_OK != res)
        keepon = FALSE;
    }

    if(!keepon)
      ;
    else if(gotbytes <= 0) {
      keepon = FALSE;
      result = CURLE_RECV_ERROR;
      failf(data, "FTP response reading failed");
    }
    else {
      /* we got a whole chunk of data, which can be anything from one
       * byte to a set of lines and possible just a piece of the last
       * line */
      int i;

      conn->headerbytecount += gotbytes;

      ftp->nread_resp += gotbytes;
      for(i = 0; i < gotbytes; ptr++, i++) {
        perline++;
        if(*ptr=='\n') {
          /* a newline is CRLF in ftp-talk, so the CR is ignored as
             the line isn't really terminated until the LF comes */

          /* output debug output if that is requested */
          if(data->set.verbose)
            Curl_debug(data, CURLINFO_HEADER_IN, line_start, perline, conn);

          /*
           * We pass all response-lines to the callback function registered
           * for "headers". The response lines can be seen as a kind of
           * headers.
           */
          result = Curl_client_write(data, CLIENTWRITE_HEADER,
                                     line_start, perline);
          if(result)
            return result;

#define lastline(line) (isdigit((int)line[0]) && isdigit((int)line[1]) && \
                        isdigit((int)line[2]) && (' ' == line[3]))

          if(perline>3 && lastline(line_start)) {
            /* This is the end of the last line, copy the last line to the
               start of the buffer and zero terminate, for old times sake (and
               krb4)! */
            char *meow;
            int n;
            for(meow=line_start, n=0; meow<ptr; meow++, n++)
              buf[n] = *meow;
            *meow=0; /* zero terminate */
            keepon=FALSE;
            line_start = ptr+1; /* advance pointer */
            i++; /* skip this before getting out */

            *size = ftp->nread_resp; /* size of the response */
            ftp->nread_resp = 0; /* restart */
            break;
          }
          perline=0; /* line starts over here */
          line_start = ptr+1;
        }
      }
      if(!keepon && (i != gotbytes)) {
        /* We found the end of the response lines, but we didn't parse the
           full chunk of data we have read from the server. We therefore need
           to store the rest of the data to be checked on the next invoke as
           it may actually contain another end of response already! */
        ftp->cache_size = gotbytes - i;
        ftp->cache = (char *)malloc((int)ftp->cache_size);
        if(ftp->cache)
          memcpy(ftp->cache, line_start, (int)ftp->cache_size);
        else
          return CURLE_OUT_OF_MEMORY; /**BANG**/
      }
    } /* there was data */

  } /* while there's buffer left and loop is requested */

  if(!result)
    code = atoi(buf);

#ifdef HAVE_KRB4
  /* handle the security-oriented responses 6xx ***/
  /* FIXME: some errorchecking perhaps... ***/
  switch(code) {
  case 631:
    Curl_sec_read_msg(conn, buf, prot_safe);
    break;
  case 632:
    Curl_sec_read_msg(conn, buf, prot_private);
    break;
  case 633:
    Curl_sec_read_msg(conn, buf, prot_confidential);
    break;
  default:
    /* normal ftp stuff we pass through! */
    break;
  }
#endif

  *ftpcode=code; /* return the initial number like this */


  /* store the latest code for later retrieval */
  conn->data->info.httpcode=code;

  return result;
}

/* --- parse FTP server responses --- */

/*
 * Curl_GetFTPResponse() is supposed to be invoked after each command sent to
 * a remote FTP server. This function will wait and read all lines of the
 * response and extract the relevant return code for the invoking function.
 */

CURLcode Curl_GetFTPResponse(ssize_t *nreadp, /* return number of bytes read */
                             struct connectdata *conn,
                             int *ftpcode) /* return the ftp-code */
{
  /*
   * We cannot read just one byte per read() and then go back to select() as
   * the OpenSSL read() doesn't grok that properly.
   *
   * Alas, read as much as possible, split up into lines, use the ending
   * line in a response or continue reading.  */

  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  int perline; /* count bytes per line */
  bool keepon=TRUE;
  ssize_t gotbytes;
  char *ptr;
  long timeout;              /* timeout in seconds */
  int interval_ms;
  struct SessionHandle *data = conn->data;
  char *line_start;
  int code=0; /* default ftp "error code" to return */
  char *buf = data->state.buffer;
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct timeval now = Curl_tvnow();

  if (ftpcode)
    *ftpcode = 0; /* 0 for errors */

  ptr=buf;
  line_start = buf;

  *nreadp=0;
  perline=0;
  keepon=TRUE;

  while((*nreadp<BUFSIZE) && (keepon && !result)) {
    /* check and reset timeout value every lap */
    if(data->set.ftp_response_timeout )
      /* if CURLOPT_FTP_RESPONSE_TIMEOUT is set, use that to determine
         remaining time.  Also, use "now" as opposed to "conn->now"
         because ftp_response_timeout is only supposed to govern
         the response for any given ftp response, not for the time
         from connect to the given ftp response. */
      timeout = data->set.ftp_response_timeout - /* timeout time */
        Curl_tvdiff(Curl_tvnow(), now)/1000; /* spent time */
    else if(data->set.timeout)
      /* if timeout is requested, find out how much remaining time we have */
      timeout = data->set.timeout - /* timeout time */
        Curl_tvdiff(Curl_tvnow(), conn->now)/1000; /* spent time */
    else
      /* Even without a requested timeout, we only wait response_time
         seconds for the full response to arrive before we bail out */
      timeout = ftp->response_time -
        Curl_tvdiff(Curl_tvnow(), now)/1000; /* spent time */

    if(timeout <=0 ) {
      failf(data, "FTP response timeout");
      return CURLE_OPERATION_TIMEDOUT; /* already too little time */
    }

    if(!ftp->cache) {
      interval_ms = 1 * 1000;  /* use 1 second timeout intervals */

      switch (Curl_select(sockfd, CURL_SOCKET_BAD, interval_ms)) {
      case -1: /* select() error, stop reading */
        result = CURLE_RECV_ERROR;
        failf(data, "FTP response aborted due to select() error: %d", errno);
        break;
      case 0: /* timeout */
        if(Curl_pgrsUpdate(conn))
          return CURLE_ABORTED_BY_CALLBACK;
        continue; /* just continue in our loop for the timeout duration */

      default:
        break;
      }
    }
    if(CURLE_OK == result) {
      /*
       * This code previously didn't use the kerberos sec_read() code
       * to read, but when we use Curl_read() it may do so. Do confirm
       * that this is still ok and then remove this comment!
       */
      if(ftp->cache) {
        /* we had data in the "cache", copy that instead of doing an actual
         * read
         *
         * Dave Meyer, December 2003:
         * ftp->cache_size is cast to int here.  This should be safe,
         * because it would have been populated with something of size
         * int to begin with, even though its datatype may be larger
         * than an int.
         */
        memcpy(ptr, ftp->cache, (int)ftp->cache_size);
        gotbytes = (int)ftp->cache_size;
        free(ftp->cache);    /* free the cache */
        ftp->cache = NULL;   /* clear the pointer */
        ftp->cache_size = 0; /* zero the size just in case */
      }
      else {
        int res = Curl_read(conn, sockfd, ptr, BUFSIZE-*nreadp, &gotbytes);
        if(res < 0)
          /* EWOULDBLOCK */
          continue; /* go looping again */

        if(CURLE_OK != res)
          keepon = FALSE;
      }

      if(!keepon)
        ;
      else if(gotbytes <= 0) {
        keepon = FALSE;
        result = CURLE_RECV_ERROR;
        failf(data, "FTP response reading failed");
      }
      else {
        /* we got a whole chunk of data, which can be anything from one
         * byte to a set of lines and possible just a piece of the last
         * line */
        int i;

        conn->headerbytecount += gotbytes;

        *nreadp += gotbytes;
        for(i = 0; i < gotbytes; ptr++, i++) {
          perline++;
          if(*ptr=='\n') {
            /* a newline is CRLF in ftp-talk, so the CR is ignored as
               the line isn't really terminated until the LF comes */

            /* output debug output if that is requested */
            if(data->set.verbose)
              Curl_debug(data, CURLINFO_HEADER_IN, line_start, perline, conn);

            /*
             * We pass all response-lines to the callback function registered
             * for "headers". The response lines can be seen as a kind of
             * headers.
             */
            result = Curl_client_write(data, CLIENTWRITE_HEADER,
                                       line_start, perline);
            if(result)
              return result;

#define lastline(line) (isdigit((int)line[0]) && isdigit((int)line[1]) && \
                        isdigit((int)line[2]) && (' ' == line[3]))

            if(perline>3 && lastline(line_start)) {
              /* This is the end of the last line, copy the last
               * line to the start of the buffer and zero terminate,
               * for old times sake (and krb4)! */
              char *meow;
              int n;
              for(meow=line_start, n=0; meow<ptr; meow++, n++)
                buf[n] = *meow;
              *meow=0; /* zero terminate */
              keepon=FALSE;
              line_start = ptr+1; /* advance pointer */
              i++; /* skip this before getting out */
              break;
            }
            perline=0; /* line starts over here */
            line_start = ptr+1;
          }
        }
        if(!keepon && (i != gotbytes)) {
          /* We found the end of the response lines, but we didn't parse the
             full chunk of data we have read from the server. We therefore
             need to store the rest of the data to be checked on the next
             invoke as it may actually contain another end of response
             already!  Cleverly figured out by Eric Lavigne in December
             2001. */
          ftp->cache_size = gotbytes - i;
          ftp->cache = (char *)malloc((int)ftp->cache_size);
          if(ftp->cache)
            memcpy(ftp->cache, line_start, (int)ftp->cache_size);
          else
            return CURLE_OUT_OF_MEMORY; /**BANG**/
        }
      } /* there was data */
    } /* if(no error) */
  } /* while there's buffer left and loop is requested */

  if(!result)
    code = atoi(buf);

#ifdef HAVE_KRB4
  /* handle the security-oriented responses 6xx ***/
  /* FIXME: some errorchecking perhaps... ***/
  switch(code) {
  case 631:
    Curl_sec_read_msg(conn, buf, prot_safe);
    break;
  case 632:
    Curl_sec_read_msg(conn, buf, prot_private);
    break;
  case 633:
    Curl_sec_read_msg(conn, buf, prot_confidential);
    break;
  default:
    /* normal ftp stuff we pass through! */
    break;
  }
#endif

  if(ftpcode)
    *ftpcode=code; /* return the initial number like this */

  /* store the latest code for later retrieval */
  conn->data->info.httpcode=code;

  return result;
}

/* This is the ONLY way to change FTP state! */
static void state(struct connectdata *conn,
                  ftpstate state)
{
#ifdef CURLDEBUG
  /* for debug purposes */
  const char *names[]={
    "STOP",
    "WAIT220",
    "AUTH",
    "USER",
    "PASS",
    "ACCT",
    "PBSZ",
    "PROT",
    "PWD",
    "QUOTE",
    "RETR_PREQUOTE",
    "STOR_PREQUOTE",
    "POSTQUOTE",
    "CWD",
    "MKD",
    "MDTM",
    "TYPE",
    "LIST_TYPE",
    "RETR_TYPE",
    "STOR_TYPE",
    "SIZE",
    "RETR_SIZE",
    "STOR_SIZE",
    "REST",
    "RETR_REST",
    "PORT",
    "PASV",
    "LIST",
    "RETR",
    "STOR",
    "QUIT"
  };
#endif
  struct FTP *ftp = conn->proto.ftp;
#ifdef CURLDEBUG
  if(ftp->state != state)
    infof(conn->data, "FTP %p state change from %s to %s\n",
          ftp, names[ftp->state], names[state]);
#endif
  ftp->state = state;
}

static CURLcode ftp_state_user(struct connectdata *conn)
{
  CURLcode result;
  struct FTP *ftp = conn->proto.ftp;
  /* send USER */
  NBFTPSENDF(conn, "USER %s", ftp->user?ftp->user:"");

  state(conn, FTP_USER);

  return CURLE_OK;
}

static CURLcode ftp_state_pwd(struct connectdata *conn)
{
  CURLcode result;

  /* send PWD to discover our entry point */
  NBFTPSENDF(conn, "PWD", NULL);
  state(conn, FTP_PWD);

  return CURLE_OK;
}

/* For the FTP "protocol connect" and "doing" phases only */
CURLcode Curl_ftp_fdset(struct connectdata *conn,
                        fd_set *read_fd_set,
                        fd_set *write_fd_set,
                        int *max_fdp)
{
  struct FTP *ftp = conn->proto.ftp;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];

  if(ftp->sendleft) {
    /* write mode */
    FD_SET(sockfd, write_fd_set);
  }
  else {
    /* read mode */
    FD_SET(sockfd, read_fd_set);
  }

  if((int)sockfd > *max_fdp)
    *max_fdp = (int)sockfd;

  return CURLE_OK;
}

/* This is called after the FTP_QUOTE state is passed.

   ftp_state_cwd() sends the range of PWD commands to the server to change to
   the correct directory. It may also need to send MKD commands to create
   missing ones, if that option is enabled.
*/
static CURLcode ftp_state_cwd(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;

  if(ftp->cwddone)
    /* already done and fine */
    result = ftp_state_post_cwd(conn);
  else {
    ftp->count2 = 0;
    if (conn->bits.reuse && ftp->entrypath) {
      /* This is a re-used connection. Since we change directory to where the
         transfer is taking place, we must first get back to the original dir
         where we ended up after login: */
      ftp->count1 = 0; /* we count this as the first path, then we add one
                          for all upcoming ones in the ftp->dirs[] array */
      NBFTPSENDF(conn, "CWD %s", ftp->entrypath);
      state(conn, FTP_CWD);
    }
    else {
      if(ftp->dirdepth) {
        ftp->count1 = 1;
        /* issue the first CWD, the rest is sent when the CWD responses are
           received... */
        NBFTPSENDF(conn, "CWD %s", ftp->dirs[ftp->count1 -1]);
        state(conn, FTP_CWD);
      }
      else {
        /* No CWD necessary */
        result = ftp_state_post_cwd(conn);
      }
    }
  }
  return result;
}

typedef enum { EPRT, LPRT, PORT, DONE } ftpport;

static CURLcode ftp_state_use_port(struct connectdata *conn,
                                   ftpport fcmd) /* start with this */

{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data=conn->data;
  curl_socket_t portsock= CURL_SOCKET_BAD;

#ifdef ENABLE_IPV6
  /******************************************************************
   * IPv6-specific section
   */

  struct addrinfo *res, *ai;
  struct sockaddr_storage ss;
  socklen_t sslen;
  char hbuf[NI_MAXHOST];
  struct sockaddr *sa=(struct sockaddr *)&ss;
  unsigned char *ap;
  unsigned char *pp;
  char portmsgbuf[1024], tmp[1024];
  const char *mode[] = { "EPRT", "LPRT", "PORT", NULL };
  int rc;
  int error;
  char *host=NULL;
  struct Curl_dns_entry *h=NULL;

  if(data->set.ftpport && (strlen(data->set.ftpport) > 1)) {
    /* attempt to get the address of the given interface name */
    if(!Curl_if2ip(data->set.ftpport, hbuf, sizeof(hbuf)))
      /* not an interface, use the given string as host name instead */
      host = data->set.ftpport;
    else
      host = hbuf; /* use the hbuf for host name */
  } /* data->set.ftpport */

  if(!host) {
    /* not an interface and not a host name, get default by extracting
       the IP from the control connection */

    sslen = sizeof(ss);
    rc = getsockname(conn->sock[FIRSTSOCKET], (struct sockaddr *)&ss, &sslen);
    if(rc < 0) {
      failf(data, "getsockname() returned %d\n", rc);
      return CURLE_FTP_PORT_FAILED;
    }

    rc = getnameinfo((struct sockaddr *)&ss, sslen, hbuf, sizeof(hbuf), NULL,
                     0, NIFLAGS);
    if(rc) {
      failf(data, "getnameinfo() returned %d\n", rc);
      return CURLE_FTP_PORT_FAILED;
    }
    host = hbuf; /* use this host name */
  }

  rc = Curl_resolv(conn, host, 0, &h);
  if(rc == CURLRESOLV_PENDING)
    rc = Curl_wait_for_resolv(conn, &h);
  if(h) {
    res = h->addr;
    /* when we return from this function, we can forget about this entry
       to we can unlock it now already */
    Curl_resolv_unlock(data, h);
  } /* (h) */
  else
    res = NULL; /* failure! */

  portsock = CURL_SOCKET_BAD;
  error = 0;
  for (ai = res; ai; ai = ai->ai_next) {
    /*
     * Workaround for AIX5 getaddrinfo() problem (it doesn't set ai_socktype):
     */
    if (ai->ai_socktype == 0)
      ai->ai_socktype = SOCK_STREAM;

    portsock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (portsock == CURL_SOCKET_BAD) {
      error = Curl_ourerrno();
      continue;
    }

    if (bind(portsock, ai->ai_addr, ai->ai_addrlen) < 0) {
      error = Curl_ourerrno();
      sclose(portsock);
      portsock = CURL_SOCKET_BAD;
      continue;
    }

    if (listen(portsock, 1) < 0) {
      error = Curl_ourerrno();
      sclose(portsock);
      portsock = CURL_SOCKET_BAD;
      continue;
    }

    break;
  }

  if (portsock == CURL_SOCKET_BAD) {
    failf(data, "%s", Curl_strerror(conn,error));
    return CURLE_FTP_PORT_FAILED;
  }

  sslen = sizeof(ss);
  if (getsockname(portsock, sa, &sslen) < 0) {
    failf(data, "%s", Curl_strerror(conn,Curl_ourerrno()));
    return CURLE_FTP_PORT_FAILED;
  }

#ifdef PF_INET6
  if(!conn->bits.ftp_use_eprt && conn->bits.ipv6)
    /* EPRT is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPRT again! */
    conn->bits.ftp_use_eprt = TRUE;
#endif

  for (; fcmd != DONE; fcmd++) {
    int lprtaf, eprtaf;
    int alen=0, plen=0;

    if(!conn->bits.ftp_use_eprt && (EPRT == fcmd))
      /* if disabled, goto next */
      continue;

    if(!conn->bits.ftp_use_lprt && (LPRT == fcmd))
      /* if disabled, goto next */
      continue;

    switch (sa->sa_family) {
    case AF_INET:
      ap = (unsigned char *)&((struct sockaddr_in *)&ss)->sin_addr;
      alen = sizeof(((struct sockaddr_in *)&ss)->sin_addr);
      pp = (unsigned char *)&((struct sockaddr_in *)&ss)->sin_port;
      plen = sizeof(((struct sockaddr_in *)&ss)->sin_port);
      lprtaf = 4;
      eprtaf = 1;
      break;
    case AF_INET6:
      ap = (unsigned char *)&((struct sockaddr_in6 *)&ss)->sin6_addr;
      alen = sizeof(((struct sockaddr_in6 *)&ss)->sin6_addr);
      pp = (unsigned char *)&((struct sockaddr_in6 *)&ss)->sin6_port;
      plen = sizeof(((struct sockaddr_in6 *)&ss)->sin6_port);
      lprtaf = 6;
      eprtaf = 2;
      break;
    default:
      ap = pp = NULL;
      lprtaf = eprtaf = -1;
      break;
    }

    if (EPRT == fcmd) {
      if (eprtaf < 0)
        continue;
      if (getnameinfo((struct sockaddr *)&ss, sslen,
                      portmsgbuf, sizeof(portmsgbuf), tmp, sizeof(tmp),
                      NIFLAGS))
        continue;

      /* do not transmit IPv6 scope identifier to the wire */
      if (sa->sa_family == AF_INET6) {
        char *q = strchr(portmsgbuf, '%');
        if (q)
          *q = '\0';
      }

      result = Curl_nbftpsendf(conn, "%s |%d|%s|%s|", mode[fcmd], eprtaf,
                               portmsgbuf, tmp);
      if(result)
        return result;
      break;
    }
    else if ((LPRT == fcmd) || (PORT == fcmd)) {
      int i;

      if ((LPRT == fcmd) && lprtaf < 0)
        continue;
      if ((PORT == fcmd) && sa->sa_family != AF_INET)
        continue;

      portmsgbuf[0] = '\0';
      if (LPRT == fcmd) {
        snprintf(tmp, sizeof(tmp), "%d,%d", lprtaf, alen);
        if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >=
            sizeof(portmsgbuf)) {
          continue;
        }
      }

      for (i = 0; i < alen; i++) {
        if (portmsgbuf[0])
          snprintf(tmp, sizeof(tmp), ",%u", ap[i]);
        else
          snprintf(tmp, sizeof(tmp), "%u", ap[i]);

        if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >=
            sizeof(portmsgbuf)) {
          continue;
        }
      }

      if (LPRT == fcmd) {
        snprintf(tmp, sizeof(tmp), ",%d", plen);

        if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >= sizeof(portmsgbuf))
          continue;
      }

      for (i = 0; i < plen; i++) {
        snprintf(tmp, sizeof(tmp), ",%u", pp[i]);

        if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >=
            sizeof(portmsgbuf)) {
          continue;
        }
      }

      result = Curl_nbftpsendf(conn, "%s %s", mode[fcmd], portmsgbuf);
      if(result)
        return result;
      break;
    }
  }

  /* store which command was sent */
  ftp->count1 = fcmd;

  /* we set the secondary socket variable to this for now, it is only so that
     the cleanup function will close it in case we fail before the true
     secondary stuff is made */
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
    sclose(conn->sock[SECONDARYSOCKET]);
  conn->sock[SECONDARYSOCKET] = portsock;

#else
  /******************************************************************
   * IPv4-specific section
   */
  struct sockaddr_in sa;
  unsigned short porttouse;
  char myhost[256] = "";
  bool sa_filled_in = FALSE;
  Curl_addrinfo *addr = NULL;
  unsigned short ip[4];
  (void)fcmd; /* not used in the IPv4 code */
  if(data->set.ftpport) {
    in_addr_t in;

    /* First check if the given name is an IP address */
    in=inet_addr(data->set.ftpport);

    if(in != CURL_INADDR_NONE)
      /* this is an IPv4 address */
      addr = Curl_ip2addr(in, data->set.ftpport, 0);
    else {
      if(Curl_if2ip(data->set.ftpport, myhost, sizeof(myhost))) {
        /* The interface to IP conversion provided a dotted address */
        in=inet_addr(myhost);
        addr = Curl_ip2addr(in, myhost, 0);
      }
      else if(strlen(data->set.ftpport)> 1) {
        /* might be a host name! */
        struct Curl_dns_entry *h=NULL;
        int rc = Curl_resolv(conn, myhost, 0, &h);
        if(rc == CURLRESOLV_PENDING)
          /* BLOCKING */
          rc = Curl_wait_for_resolv(conn, &h);
        if(h) {
          addr = h->addr;
          /* when we return from this function, we can forget about this entry
             so we can unlock it now already */
          Curl_resolv_unlock(data, h);
        } /* (h) */
      } /* strlen */
    } /* CURL_INADDR_NONE */
  } /* data->set.ftpport */

  if(!addr) {
    /* pick a suitable default here */

    socklen_t sslen;

    sslen = sizeof(sa);
    if (getsockname(conn->sock[FIRSTSOCKET],
                    (struct sockaddr *)&sa, &sslen) < 0) {
      failf(data, "getsockname() failed");
      return CURLE_FTP_PORT_FAILED;
    }

    sa_filled_in = TRUE; /* the sa struct is filled in */
  }

  if (addr || sa_filled_in) {
    portsock = socket(AF_INET, SOCK_STREAM, 0);
    if(CURL_SOCKET_BAD != portsock) {
      socklen_t size;

      /* we set the secondary socket variable to this for now, it
         is only so that the cleanup function will close it in case
         we fail before the true secondary stuff is made */
      if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
        sclose(conn->sock[SECONDARYSOCKET]);
      conn->sock[SECONDARYSOCKET] = portsock;

      if(!sa_filled_in) {
        memcpy(&sa, addr->ai_addr, sizeof(sa));
        sa.sin_addr.s_addr = INADDR_ANY;
      }

      sa.sin_port = 0;
      size = sizeof(sa);

      if(bind(portsock, (struct sockaddr *)&sa, size) >= 0) {
        /* we succeeded to bind */
        struct sockaddr_in add;
        socklen_t socksize = sizeof(add);

        if(getsockname(portsock, (struct sockaddr *) &add,
                       &socksize)<0) {
          failf(data, "getsockname() failed");
          return CURLE_FTP_PORT_FAILED;
        }
        porttouse = ntohs(add.sin_port);

        if ( listen(portsock, 1) < 0 ) {
          failf(data, "listen(2) failed on socket");
          return CURLE_FTP_PORT_FAILED;
        }
      }
      else {
        failf(data, "bind(2) failed on socket");
        return CURLE_FTP_PORT_FAILED;
      }
    }
    else {
      failf(data, "socket(2) failed (%s)");
      return CURLE_FTP_PORT_FAILED;
    }
  }
  else {
    failf(data, "could't find IP address to use");
    return CURLE_FTP_PORT_FAILED;
  }

  if(sa_filled_in)
    Curl_inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr,
                   myhost, sizeof(myhost));
  else
    Curl_printable_address(addr, myhost, sizeof(myhost));

  if(4 == sscanf(myhost, "%hu.%hu.%hu.%hu",
                 &ip[0], &ip[1], &ip[2], &ip[3])) {

    infof(data, "Telling server to connect to %d.%d.%d.%d:%d\n",
          ip[0], ip[1], ip[2], ip[3], porttouse);

    result=Curl_nbftpsendf(conn, "PORT %d,%d,%d,%d,%d,%d",
                           ip[0], ip[1], ip[2], ip[3],
                           porttouse >> 8, porttouse & 255);
    if(result)
      return result;
  }
  else
    return CURLE_FTP_PORT_FAILED;

  Curl_freeaddrinfo(addr);

  ftp->count1 = PORT;

#endif /* end of ipv4-specific code */

  state(conn, FTP_PORT);
  return result;
}

static CURLcode ftp_state_use_pasv(struct connectdata *conn)
{
  struct FTP *ftp = conn->proto.ftp;
  CURLcode result = CURLE_OK;
  /*
    Here's the excecutive summary on what to do:

    PASV is RFC959, expect:
    227 Entering Passive Mode (a1,a2,a3,a4,p1,p2)

    LPSV is RFC1639, expect:
    228 Entering Long Passive Mode (4,4,a1,a2,a3,a4,2,p1,p2)

    EPSV is RFC2428, expect:
    229 Entering Extended Passive Mode (|||port|)

  */

  const char *mode[] = { "EPSV", "PASV", NULL };
  int modeoff;

#ifdef PF_INET6
  if(!conn->bits.ftp_use_epsv && conn->bits.ipv6)
    /* EPSV is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPSV again! */
    conn->bits.ftp_use_epsv = TRUE;
#endif

  modeoff = conn->bits.ftp_use_epsv?0:1;

  result = Curl_nbftpsendf(conn, "%s", mode[modeoff]);
  if(result)
    return result;

  ftp->count1 = modeoff;
  state(conn, FTP_PASV);
  infof(conn->data, "Connect data stream passively\n");

  return result;
}

/* REST is the last command in the chain of commands when a "head"-like
   request is made. Thus, if an actual transfer is to be made this is where
   we take off for real. */
static CURLcode ftp_state_post_rest(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;

  if(ftp->no_transfer || conn->bits.no_body) {
    /* then we're done with a "head"-like request, goto STOP */
    state(conn, FTP_STOP);

    /* doesn't transfer any data */
    ftp->no_transfer = TRUE;
  }
  else if(data->set.ftp_use_port) {
    /* We have chosen to use the PORT (or similar) command */
    result = ftp_state_use_port(conn, EPRT);
  }
  else {
    /* We have chosen (this is default) to use the PASV (or similar) command */
    result = ftp_state_use_pasv(conn);
  }
  return result;
}

static CURLcode ftp_state_post_size(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;

  if(ftp->no_transfer) {
    /* if a "head"-like request is being made */

    /* Determine if server can respond to REST command and therefore
       whether it supports range */
    NBFTPSENDF(conn, "REST %d", 0);

    state(conn, FTP_REST);
  }
  else
    result = ftp_state_post_rest(conn);

  return result;
}

static CURLcode ftp_state_post_type(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;

  if(ftp->no_transfer) {
    /* if a "head"-like request is being made */

    /* we know ftp->file is a valid pointer to a file name */
    NBFTPSENDF(conn, "SIZE %s", ftp->file);

    state(conn, FTP_SIZE);
  }
  else
    result = ftp_state_post_size(conn);

  return result;
}

static CURLcode ftp_state_post_listtype(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  /* If this output is to be machine-parsed, the NLST command might be better
     to use, since the LIST command output is not specified or standard in any
     way. It has turned out that the NLST list output is not the same on all
     servers either... */

  NBFTPSENDF(conn, "%s",
             data->set.customrequest?data->set.customrequest:
             (data->set.ftp_list_only?"NLST":"LIST"));

  state(conn, FTP_LIST);

  return result;
}

static CURLcode ftp_state_post_retrtype(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* We've sent the TYPE, now we must send the list of prequote strings */

  result = ftp_state_quote(conn, TRUE, FTP_RETR_PREQUOTE);

  return result;
}

static CURLcode ftp_state_post_stortype(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* We've sent the TYPE, now we must send the list of prequote strings */

  result = ftp_state_quote(conn, TRUE, FTP_STOR_PREQUOTE);

  return result;
}

static CURLcode ftp_state_post_mdtm(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;

  /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which in FTP can't be much more than the file size and
     date. */
  if(conn->bits.no_body && data->set.include_header && ftp->file) {
    /* The SIZE command is _not_ RFC 959 specified, and therefor many servers
       may not support it! It is however the only way we have to get a file's
       size! */

    ftp->no_transfer = TRUE; /* this means no actual transfer will be made */

    /* Some servers return different sizes for different modes, and thus we
       must set the proper type before we check the size */
    NBFTPSENDF(conn, "TYPE %c",
               data->set.ftp_ascii?'A':'I');
    state(conn, FTP_TYPE);
  }
  else
    result = ftp_state_post_type(conn);

  return result;
}

/* This is called after the CWD commands have been done in the beginning of
   the DO phase */
static CURLcode ftp_state_post_cwd(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;

  /* Requested time of file or time-depended transfer? */
  if((data->set.get_filetime || data->set.timecondition) && ftp->file) {

    /* we have requested to get the modified-time of the file, this is a white
       spot as the MDTM is not mentioned in RFC959 */
    NBFTPSENDF(conn, "MDTM %s", ftp->file);

    state(conn, FTP_MDTM);
  }
  else
    result = ftp_state_post_mdtm(conn);

  return result;
}


/* This is called after the TYPE and possible quote commands have been sent */
static CURLcode ftp_state_ul_setup(struct connectdata *conn,
                                   bool sizechecked)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;
  curl_off_t passed=0;

  if((conn->resume_from && !sizechecked) ||
     ((conn->resume_from > 0) && sizechecked)) {
    /* we're about to continue the uploading of a file */
    /* 1. get already existing file's size. We use the SIZE command for this
       which may not exist in the server!  The SIZE command is not in
       RFC959. */

    /* 2. This used to set REST. But since we can do append, we
       don't another ftp command. We just skip the source file
       offset and then we APPEND the rest on the file instead */

    /* 3. pass file-size number of bytes in the source file */
    /* 4. lower the infilesize counter */
    /* => transfer as usual */

    if(conn->resume_from < 0 ) {
      /* Got no given size to start from, figure it out */
      NBFTPSENDF(conn, "SIZE %s", ftp->file);
      state(conn, FTP_STOR_SIZE);
      return result;
    }

    /* enable append */
    data->set.ftp_append = TRUE;

    /* Let's read off the proper amount of bytes from the input. If we knew it
       was a proper file we could've just fseek()ed but we only have a stream
       here */

    /* TODO: allow the ioctlfunction to provide a fast forward function that
       can be used here and use this method only as a fallback! */
    do {
      curl_off_t readthisamountnow = (conn->resume_from - passed);
      curl_off_t actuallyread;

      if(readthisamountnow > BUFSIZE)
        readthisamountnow = BUFSIZE;

      actuallyread = (curl_off_t)
        conn->fread(data->state.buffer, 1, (size_t)readthisamountnow,
                    conn->fread_in);

      passed += actuallyread;
      if(actuallyread != readthisamountnow) {
        failf(data, "Could only read %" FORMAT_OFF_T
              " bytes from the input", passed);
        return CURLE_FTP_COULDNT_USE_REST;
      }
    } while(passed != conn->resume_from);

    /* now, decrease the size of the read */
    if(data->set.infilesize>0) {
      data->set.infilesize -= conn->resume_from;

      if(data->set.infilesize <= 0) {
        infof(data, "File already completely uploaded\n");

        /* no data to transfer */
        result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

        /* Set no_transfer so that we won't get any error in
         * Curl_ftp_done() because we didn't transfer anything! */
        ftp->no_transfer = TRUE;

        state(conn, FTP_STOP);
        return CURLE_OK;
      }
    }
    /* we've passed, proceed as normal */
  } /* resume_from */

  NBFTPSENDF(conn, data->set.ftp_append?"APPE %s":"STOR %s",
             ftp->file);

  state(conn, FTP_STOR);

  return result;
}

static CURLcode ftp_state_quote(struct connectdata *conn,
                                bool init,
                                ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;
  bool quote=FALSE;
  struct curl_slist *item;

  switch(instate) {
  case FTP_QUOTE:
  default:
    item = data->set.quote;
    break;
  case FTP_RETR_PREQUOTE:
  case FTP_STOR_PREQUOTE:
    item = data->set.prequote;
    break;
  case FTP_POSTQUOTE:
    item = data->set.postquote;
    break;
  }

  if(init)
    ftp->count1 = 0;
  else
    ftp->count1++;

  if(item) {
    int i = 0;

    /* Skip count1 items in the linked list */
    while((i< ftp->count1) && item) {
      item = item->next;
      i++;
    }
    if(item) {
      NBFTPSENDF(conn, "%s", item->data);
      state(conn, instate);
      quote = TRUE;
    }
  }

  if(!quote) {
    /* No more quote to send, continue to ... */
    switch(instate) {
    case FTP_QUOTE:
    default:
      result = ftp_state_cwd(conn);
      break;
    case FTP_RETR_PREQUOTE:
      NBFTPSENDF(conn, "SIZE %s", ftp->file);
      state(conn, FTP_RETR_SIZE);
      break;
    case FTP_STOR_PREQUOTE:
      result = ftp_state_ul_setup(conn, FALSE);
      break;
    case FTP_POSTQUOTE:
      break;
    }
  }

  return result;
}

static CURLcode ftp_state_pasv_resp(struct connectdata *conn,
                                    int ftpcode)
{
  struct FTP *ftp = conn->proto.ftp;
  CURLcode result;
  struct SessionHandle *data=conn->data;
  Curl_addrinfo *conninfo;
  struct Curl_dns_entry *addr=NULL;
  int rc;
  unsigned short connectport; /* the local port connect() should use! */
  unsigned short newport=0; /* remote port */
  bool connected;

  /* newhost must be able to hold a full IP-style address in ASCII, which
     in the IPv6 case means 5*8-1 = 39 letters */
#define NEWHOST_BUFSIZE 48
  char newhost[NEWHOST_BUFSIZE];
  char *str=&data->state.buffer[4];  /* start on the first letter */

  if((ftp->count1 == 0) &&
     (ftpcode == 229)) {
    /* positive EPSV response */
    char *ptr = strchr(str, '(');
    if(ptr) {
      unsigned int num;
      char separator[4];
      ptr++;
      if(5  == sscanf(ptr, "%c%c%c%u%c",
                      &separator[0],
                      &separator[1],
                      &separator[2],
                      &num,
                      &separator[3])) {
        const char sep1 = separator[0];
        int i;

        /* The four separators should be identical, or else this is an oddly
           formatted reply and we bail out immediately. */
        for(i=1; i<4; i++) {
          if(separator[i] != sep1) {
            ptr=NULL; /* set to NULL to signal error */
            break;
          }
        }
        if(ptr) {
          newport = num;

          /* use the same IP we are already connected to */
          snprintf(newhost, NEWHOST_BUFSIZE, "%s", conn->ip_addr_str);
        }
      }
      else
        ptr=NULL;
    }
    if(!ptr) {
      failf(data, "Weirdly formatted EPSV reply");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
  }
  else if((ftp->count1 == 1) &&
          (ftpcode == 227)) {
    /* positive PASV response */
    int ip[4];
    int port[2];

    /*
     * Scan for a sequence of six comma-separated numbers and use them as
     * IP+port indicators.
     *
     * Found reply-strings include:
     * "227 Entering Passive Mode (127,0,0,1,4,51)"
     * "227 Data transfer will passively listen to 127,0,0,1,4,51"
     * "227 Entering passive mode. 127,0,0,1,4,51"
     */
    while(*str) {
      if (6 == sscanf(str, "%d,%d,%d,%d,%d,%d",
                      &ip[0], &ip[1], &ip[2], &ip[3],
                      &port[0], &port[1]))
        break;
      str++;
    }

    if(!*str) {
      failf(data, "Couldn't interpret the 227-response");
      return CURLE_FTP_WEIRD_227_FORMAT;
    }

    snprintf(newhost, sizeof(newhost),
             "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    newport = (port[0]<<8) + port[1];
  }
  else if(ftp->count1 == 0) {
    /* EPSV failed, move on to PASV */

    /* disable it for next transfer */
    conn->bits.ftp_use_epsv = FALSE;
    infof(data, "disabling EPSV usage\n");

    NBFTPSENDF(conn, "PASV", NULL);
    ftp->count1++;
    /* remain in the FTP_PASV state */
    return result;
  }
  else {
    failf(data, "Bad PASV/EPSV response: %03d", ftpcode);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

  /* we got OK from server */

  if(data->change.proxy && *data->change.proxy) {
    /*
     * This is a tunnel through a http proxy and we need to connect to the
     * proxy again here.
     *
     * We don't want to rely on a former host lookup that might've expired
     * now, instead we remake the lookup here and now!
     */
    rc = Curl_resolv(conn, conn->proxy.name, (int)conn->port, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING */
      rc = Curl_wait_for_resolv(conn, &addr);

    connectport =
      (unsigned short)conn->port; /* we connect to the proxy's port */

  }
  else {
    /* normal, direct, ftp connection */
    rc = Curl_resolv(conn, newhost, newport, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING */
      rc = Curl_wait_for_resolv(conn, &addr);

    if(!addr) {
      failf(data, "Can't resolve new host %s:%d", newhost, newport);
      return CURLE_FTP_CANT_GET_HOST;
    }
    connectport = newport; /* we connect to the remote port */
  }

  result = Curl_connecthost(conn,
                            addr,
                            &conn->sock[SECONDARYSOCKET],
                            &conninfo,
                            &connected);

  Curl_resolv_unlock(data, addr); /* we're done using this address */

  if(result)
    return result;

  conn->bits.tcpconnect = connected; /* simply TRUE or FALSE */

  /*
   * When this is used from the multi interface, this might've returned with
   * the 'connected' set to FALSE and thus we are now awaiting a non-blocking
   * connect to connect and we should not be "hanging" here waiting.
   */

  if(data->set.verbose)
    /* this just dumps information about this second connection */
    ftp_pasv_verbose(conn, conninfo, newhost, connectport);

#ifndef CURL_DISABLE_HTTP
  if(conn->bits.tunnel_proxy) {
    /* FIX: this MUST wait for a proper connect first if 'connected' is
     * FALSE */

    /* BLOCKING */
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = Curl_ConnectHTTPProxyTunnel(conn, SECONDARYSOCKET,
                                         newhost, newport);
    if(CURLE_OK != result)
      return result;
  }
#endif   /* CURL_DISABLE_HTTP */

  state(conn, FTP_STOP); /* this phase is completed */

  return result;
}

static CURLcode ftp_state_port_resp(struct connectdata *conn,
                                    int ftpcode)
{
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;
  ftpport fcmd = (ftpport)ftp->count1;
  CURLcode result = CURLE_OK;

  if(ftpcode != 200) {
    /* the command failed */

    if (EPRT == fcmd) {
      infof(data, "disabling EPRT usage\n");
      conn->bits.ftp_use_eprt = FALSE;
    }
    else if (LPRT == fcmd) {
      infof(data, "disabling LPRT usage\n");
      conn->bits.ftp_use_lprt = FALSE;
    }
    fcmd++;

    if(fcmd == DONE) {
      failf(data, "Failed to do PORT");
      result = CURLE_FTP_PORT_FAILED;
    }
    else
      /* try next */
      result = ftp_state_use_port(conn, fcmd);
  }
  else {
    infof(data, "Connect data stream actively\n");
    state(conn, FTP_STOP); /* end of DO phase */
  }

  return result;
}

static CURLcode ftp_state_mdtm_resp(struct connectdata *conn,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data=conn->data;

  switch(ftpcode) {
  case 213:
    {
      /* we got a time. Format should be: "YYYYMMDDHHMMSS[.sss]" where the
         last .sss part is optional and means fractions of a second */
      int year, month, day, hour, minute, second;
      char *buf = data->state.buffer;
      if(6 == sscanf(buf+4, "%04d%02d%02d%02d%02d%02d",
                     &year, &month, &day, &hour, &minute, &second)) {
        /* we have a time, reformat it */
        time_t secs=time(NULL);
        /* using the good old yacc/bison yuck */
        snprintf(buf, sizeof(conn->data->state.buffer),
                 "%04d%02d%02d %02d:%02d:%02d GMT",
                 year, month, day, hour, minute, second);
        /* now, convert this into a time() value: */
        data->info.filetime = curl_getdate(buf, &secs);
      }

      /* If we asked for a time of the file and we actually got one as well,
         we "emulate" a HTTP-style header in our output. */

      if(conn->bits.no_body &&
         data->set.include_header &&
         ftp->file &&
         data->set.get_filetime &&
         (data->info.filetime>=0) ) {
        struct tm *tm;
        time_t clock = (time_t)data->info.filetime;
#ifdef HAVE_GMTIME_R
        struct tm buffer;
        tm = (struct tm *)gmtime_r(&clock, &buffer);
#else
        tm = gmtime(&clock);
#endif
        /* format: "Tue, 15 Nov 1994 12:45:26" */
        snprintf(buf, BUFSIZE-1,
                 "Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n",
                 Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
                 tm->tm_mday,
                 Curl_month[tm->tm_mon],
                 tm->tm_year + 1900,
                 tm->tm_hour,
                 tm->tm_min,
                 tm->tm_sec);
        result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
        if(result)
          return result;
      } /* end of a ridiculous amount of conditionals */
    }
    break;
  default:
    infof(data, "unsupported MDTM reply format\n");
    break;
  case 550: /* "No such file or directory" */
    failf(data, "Given file does not exist");
    result = CURLE_FTP_COULDNT_RETR_FILE;
    break;
  }

  if(data->set.timecondition) {
    if((data->info.filetime > 0) && (data->set.timevalue > 0)) {
      switch(data->set.timecondition) {
      case CURL_TIMECOND_IFMODSINCE:
      default:
        if(data->info.filetime < data->set.timevalue) {
          infof(data, "The requested document is not new enough\n");
          ftp->no_transfer = TRUE; /* mark this to not transfer data */
          state(conn, FTP_STOP);
          return CURLE_OK;
        }
        break;
      case CURL_TIMECOND_IFUNMODSINCE:
        if(data->info.filetime > data->set.timevalue) {
          infof(data, "The requested document is not old enough\n");
          ftp->no_transfer = TRUE; /* mark this to not transfer data */
          state(conn, FTP_STOP);
          return CURLE_OK;
        }
        break;
      } /* switch */
    }
    else {
      infof(data, "Skipping time comparison\n");
    }
  }

  if(!result)
    result = ftp_state_post_mdtm(conn);

  return result;
}

static CURLcode ftp_state_type_resp(struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data=conn->data;

  if(ftpcode != 200) {
    failf(data, "Couldn't set desired mode");
    return CURLE_FTP_COULDNT_SET_BINARY; /* FIX */
  }
  if(instate == FTP_TYPE)
    result = ftp_state_post_type(conn);
  else if(instate == FTP_LIST_TYPE)
    result = ftp_state_post_listtype(conn);
  else if(instate == FTP_RETR_TYPE)
    result = ftp_state_post_retrtype(conn);
  else if(instate == FTP_STOR_TYPE)
    result = ftp_state_post_stortype(conn);

  return result;
}

static CURLcode ftp_state_post_retr_size(struct connectdata *conn,
                                         curl_off_t filesize)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data=conn->data;
  struct FTP *ftp = conn->proto.ftp;

  if (data->set.max_filesize && (filesize > data->set.max_filesize)) {
    failf(data, "Maximum file size exceeded");
    return CURLE_FILESIZE_EXCEEDED;
  }
  ftp->downloadsize = filesize;

  if(conn->resume_from) {
    /* We always (attempt to) get the size of downloads, so it is done before
       this even when not doing resumes. */
    if(filesize == -1) {
      infof(data, "ftp server doesn't support SIZE\n");
      /* We couldn't get the size and therefore we can't know if there really
         is a part of the file left to get, although the server will just
         close the connection when we start the connection so it won't cause
         us any harm, just not make us exit as nicely. */
    }
    else {
      /* We got a file size report, so we check that there actually is a
         part of the file left to get, or else we go home.  */
      if(conn->resume_from< 0) {
        /* We're supposed to download the last abs(from) bytes */
        if(filesize < -conn->resume_from) {
          failf(data, "Offset (%" FORMAT_OFF_T
                ") was beyond file size (%" FORMAT_OFF_T ")",
                conn->resume_from, filesize);
          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        /* convert to size to download */
        ftp->downloadsize = -conn->resume_from;
        /* download from where? */
        conn->resume_from = filesize - ftp->downloadsize;
      }
      else {
        if(filesize < conn->resume_from) {
          failf(data, "Offset (%" FORMAT_OFF_T
                ") was beyond file size (%" FORMAT_OFF_T ")",
                conn->resume_from, filesize);
          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        /* Now store the number of bytes we are expected to download */
        ftp->downloadsize = filesize-conn->resume_from;
      }
    }

    if(ftp->downloadsize == 0) {
      /* no data to transfer */
      result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
      infof(data, "File already completely downloaded\n");

      /* Set no_transfer so that we won't get any error in Curl_ftp_done()
       * because we didn't transfer the any file */
      ftp->no_transfer = TRUE;
      state(conn, FTP_STOP);
      return CURLE_OK;
    }

    /* Set resume file transfer offset */
    infof(data, "Instructs server to resume from offset %" FORMAT_OFF_T
          "\n", conn->resume_from);

    NBFTPSENDF(conn, "REST %" FORMAT_OFF_T, conn->resume_from);

    state(conn, FTP_RETR_REST);

  }
  else {
    /* no resume */
    NBFTPSENDF(conn, "RETR %s", ftp->file);
    state(conn, FTP_RETR);
  }

  return result;
}

static CURLcode ftp_state_size_resp(struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data=conn->data;
  curl_off_t filesize;
  char *buf = data->state.buffer;

  /* get the size from the ascii string: */
  filesize = (ftpcode == 213)?curlx_strtoofft(buf+4, NULL, 0):-1;

  if(instate == FTP_SIZE) {
    if(-1 != filesize) {
      snprintf(buf, sizeof(data->state.buffer),
               "Content-Length: %" FORMAT_OFF_T "\r\n", filesize);
      result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
      if(result)
        return result;
    }
    result = ftp_state_post_size(conn);
  }
  else if(instate == FTP_RETR_SIZE)
    result = ftp_state_post_retr_size(conn, filesize);
  else if(instate == FTP_STOR_SIZE) {
    conn->resume_from = filesize;
    result = ftp_state_ul_setup(conn, TRUE);
  }

  return result;
}

static CURLcode ftp_state_rest_resp(struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;

  switch(instate) {
  case FTP_REST:
  default:
    if (ftpcode == 350) {
      result = Curl_client_write(conn->data, CLIENTWRITE_BOTH,
                               (char *)"Accept-ranges: bytes\r\n", 0);
      if(result)
        return result;
    }

    result = ftp_state_post_rest(conn);
    break;

  case FTP_RETR_REST:
    if (ftpcode != 350) {
      failf(conn->data, "Couldn't use REST");
      result = CURLE_FTP_COULDNT_USE_REST;
    }
    else {
      NBFTPSENDF(conn, "RETR %s", ftp->file);
      state(conn, FTP_RETR);
    }
    break;
  }

  return result;
}

static CURLcode ftp_state_stor_resp(struct connectdata *conn,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;

  if(ftpcode>=400) {
    failf(data, "Failed FTP upload: %0d", ftpcode);
    /* oops, we never close the sockets! */
    return CURLE_FTP_COULDNT_STOR_FILE;
  }

  if(data->set.ftp_use_port) {
    /* BLOCKING */
    /* PORT means we are now awaiting the server to connect to us. */
    result = AllowServerConnect(conn);
    if( result )
      return result;
  }

  if(conn->ssl[SECONDARYSOCKET].use) {
    /* since we only have a plaintext TCP connection here, we must now
       do the TLS stuff */
    infof(data, "Doing the SSL/TLS handshake on the data stream\n");
    /* BLOCKING */
    result = Curl_SSLConnect(conn, SECONDARYSOCKET);
    if(result)
      return result;
  }

  *(ftp->bytecountp)=0;

  /* When we know we're uploading a specified file, we can get the file
     size prior to the actual upload. */

  Curl_pgrsSetUploadSize(data, data->set.infilesize);

  result = Curl_Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                         SECONDARYSOCKET, ftp->bytecountp);
  state(conn, FTP_STOP);

  return result;
}

/* for LIST and RETR responses */
static CURLcode ftp_state_get_resp(struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;
  char *buf = data->state.buffer;

  if((ftpcode == 150) || (ftpcode == 125)) {

    /*
      A;
      150 Opening BINARY mode data connection for /etc/passwd (2241
      bytes).  (ok, the file is being transfered)

      B:
      150 Opening ASCII mode data connection for /bin/ls

      C:
      150 ASCII data connection for /bin/ls (137.167.104.91,37445) (0 bytes).

      D:
      150 Opening ASCII mode data connection for /linux/fisk/kpanelrc (0.0.0.0,0) (545 bytes).

      E:
      125 Data connection already open; Transfer starting. */

    curl_off_t size=-1; /* default unknown size */


    /*
     * It appears that there are FTP-servers that return size 0 for files when
     * SIZE is used on the file while being in BINARY mode. To work around
     * that (stupid) behavior, we attempt to parse the RETR response even if
     * the SIZE returned size zero.
     *
     * Debugging help from Salvatore Sorrentino on February 26, 2003.
     */

    if((instate != FTP_LIST) &&
       !data->set.ftp_ascii &&
       (ftp->downloadsize < 1)) {
      /*
       * It seems directory listings either don't show the size or very
       * often uses size 0 anyway. ASCII transfers may very well turn out
       * that the transfered amount of data is not the same as this line
       * tells, why using this number in those cases only confuses us.
       *
       * Example D above makes this parsing a little tricky */
      char *bytes;
      bytes=strstr(buf, " bytes");
      if(bytes--) {
        long in=bytes-buf;
        /* this is a hint there is size information in there! ;-) */
        while(--in) {
          /* scan for the left parenthesis and break there */
          if('(' == *bytes)
            break;
          /* skip only digits */
          if(!isdigit((int)*bytes)) {
            bytes=NULL;
            break;
          }
          /* one more estep backwards */
          bytes--;
        }
        /* if we have nothing but digits: */
        if(bytes++) {
          /* get the number! */
          size = curlx_strtoofft(bytes, NULL, 0);
        }
      }
    }
    else if(ftp->downloadsize > -1)
      size = ftp->downloadsize;

    if(data->set.ftp_use_port) {
      /* BLOCKING */
      result = AllowServerConnect(conn);
      if( result )
        return result;
    }

    if(conn->ssl[SECONDARYSOCKET].use) {
      /* since we only have a plaintext TCP connection here, we must now
         do the TLS stuff */
      infof(data, "Doing the SSL/TLS handshake on the data stream\n");
      result = Curl_SSLConnect(conn, SECONDARYSOCKET);
      if(result)
        return result;
    }

    if(size > conn->maxdownload && conn->maxdownload > 0)
      size = conn->size = conn->maxdownload;

    if(instate != FTP_LIST)
      infof(data, "Getting file with size: %" FORMAT_OFF_T "\n", size);

    /* FTP download: */
    result=Curl_Transfer(conn, SECONDARYSOCKET, size, FALSE,
                         ftp->bytecountp,
                         -1, NULL); /* no upload here */
    if(result)
      return result;

    state(conn, FTP_STOP);
  }
  else {
    if((instate == FTP_LIST) && (ftpcode == 450)) {
      /* simply no matching files in the dir listing */
      ftp->no_transfer = TRUE; /* don't download anything */
      state(conn, FTP_STOP); /* this phase is over */
    }
    else {
      failf(data, "%s", buf+4);
      return CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  return result;
}

/* after USER, PASS and ACCT */
static CURLcode ftp_state_loggedin(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  infof(data, "We have successfully logged in\n");

#ifdef HAVE_KRB4
  if(data->set.krb4) {
    /* We are logged in, asked to use Kerberos. Set the requested
     * protection level
     */
    if(conn->sec_complete)
      /* BLOCKING */
      Curl_sec_set_protection_level(conn);
    
    /* We may need to issue a KAUTH here to have access to the files
     * do it if user supplied a password
     */
    if(conn->passwd && *conn->passwd) {
      /* BLOCKING */
      result = Curl_krb_kauth(conn);
      if(result)
        return result;
    }
  }
#endif
  if(conn->ssl[FIRSTSOCKET].use) {
    /* PBSZ = PROTECTION BUFFER SIZE.

    The 'draft-murray-auth-ftp-ssl' (draft 12, page 7) says:

    Specifically, the PROT command MUST be preceded by a PBSZ
    command and a PBSZ command MUST be preceded by a successful
    security data exchange (the TLS negotiation in this case)

    ... (and on page 8):

    Thus the PBSZ command must still be issued, but must have a
    parameter of '0' to indicate that no buffering is taking place
    and the data connection should not be encapsulated.
    */
    NBFTPSENDF(conn, "PBSZ %d", 0);
    state(conn, FTP_PBSZ);
  }
  else {
    result = ftp_state_pwd(conn);
  }
  return result;
}

/* for USER and PASS responses */
static CURLcode ftp_state_user_resp(struct connectdata *conn,
                                    int ftpcode,
                                    ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;
  (void)instate; /* no use for this yet */

  if((ftpcode == 331) && (ftp->state == FTP_USER)) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    NBFTPSENDF(conn, "PASS %s", ftp->passwd?ftp->passwd:"");
    state(conn, FTP_PASS);
  }
  else if(ftpcode/100 == 2) {
    /* 230 User ... logged in.
       (the user logged in with or without password) */
    result = ftp_state_loggedin(conn);
  }
  else if(ftpcode == 332) {
    if(data->set.ftp_account) {
      NBFTPSENDF(conn, "ACCT %s", data->set.ftp_account);
      state(conn, FTP_ACCT);
    }
    else {
      failf(data, "ACCT requested but none available");
      result = CURLE_LOGIN_DENIED;
    }
  }
  else {
    /* All other response codes, like:

    530 User ... access denied
    (the server denies to log the specified user) */
    failf(data, "Access denied: %03d", ftpcode);
    result = CURLE_LOGIN_DENIED;
  }
  return result;
}

/* for ACCT response */
static CURLcode ftp_state_acct_resp(struct connectdata *conn,
                                    int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  if(ftpcode != 230) {
    failf(data, "ACCT rejected by server: %03d", ftpcode);
    result = CURLE_FTP_WEIRD_PASS_REPLY; /* FIX */
  }
  else
    result = ftp_state_loggedin(conn);

  return result;
}


static CURLcode ftp_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data=conn->data;
  int ftpcode;
  struct FTP *ftp = conn->proto.ftp;
  static const char * const ftpauth[]  = {
    "SSL", "TLS"
  };
  size_t nread;

  if(ftp->sendleft) {
    /* we have a piece of a command still left to send */
    ssize_t written;
    result = Curl_write(conn, sock, ftp->sendthis + ftp->sendsize -
                        ftp->sendleft, ftp->sendleft, &written);
    if(result)
      return result;

    if(written != (ssize_t)ftp->sendleft) {
      /* only a fraction was sent */
      ftp->sendleft -= written;
    }
    else {
      free(ftp->sendthis);
      ftp->sendthis=NULL;
      ftp->sendleft = ftp->sendsize = 0;
      ftp->response = Curl_tvnow();
    }
    return CURLE_OK;
  }

  /* we read a piece of response */
  result = ftp_readresp(sock, conn, &ftpcode, &nread);
  if(result)
    return result;

  if(ftpcode) {
    /* we have now received a full FTP server response */
    switch(ftp->state) {
    case FTP_WAIT220:
      if(ftpcode != 220) {
        failf(data, "This doesn't seem like a nice ftp-server response");
        return CURLE_FTP_WEIRD_SERVER_REPLY;
      }

      /* We have received a 220 response fine, now we proceed. */
#ifdef HAVE_KRB4
      if(data->set.krb4) {
        /* If not anonymous login, try a secure login. Note that this
           procedure is still BLOCKING. */

        Curl_sec_request_prot(conn, "private");
        /* We set private first as default, in case the line below fails to
           set a valid level */
        Curl_sec_request_prot(conn, data->set.krb4_level);

        if(Curl_sec_login(conn) != 0)
          infof(data, "Logging in with password in cleartext!\n");
        else
          infof(data, "Authentication successful\n");
      }
#endif

      if(data->set.ftp_ssl && !conn->ssl[FIRSTSOCKET].use) {
        /* We don't have a SSL/TLS connection yet, but FTPS is
           requested. Try a FTPS connection now */

        ftp->count3=0;
        switch(data->set.ftpsslauth) {
        case CURLFTPAUTH_DEFAULT:
        case CURLFTPAUTH_SSL:
          ftp->count2 = 1; /* add one to get next */
          ftp->count1 = 0;
          break;
        case CURLFTPAUTH_TLS:
          ftp->count2 = -1; /* subtract one to get next */
          ftp->count1 = 1;
          break;
        default:
          failf(data, "unsupported parameter to CURLOPT_FTPSSLAUTH: %d\n",
                data->set.ftpsslauth);
          return CURLE_FAILED_INIT; /* we don't know what to do */
        }
        NBFTPSENDF(conn, "AUTH %s", ftpauth[ftp->count1]);
        state(conn, FTP_AUTH);
      }
      else {
        ftp_state_user(conn);
        if(result)
          return result;
      }

      break;

    case FTP_AUTH:
      /* we have gotten the response to a previous AUTH command */

      /* RFC2228 (page 5) says:
       *
       * If the server is willing to accept the named security mechanism,
       * and does not require any security data, it must respond with
       * reply code 234/334.
       */

      if((ftpcode == 234) || (ftpcode == 334)) {
        /* Curl_SSLConnect is BLOCKING */
        result = Curl_SSLConnect(conn, FIRSTSOCKET);
        if(result)
          return result;
        conn->protocol |= PROT_FTPS;
        conn->ssl[SECONDARYSOCKET].use = FALSE; /* clear-text data */
      }
      else if(ftp->count3 < 1) {
        ftp->count3++;
        ftp->count1 += ftp->count2; /* get next attempt */
        NBFTPSENDF(conn, "AUTH %s", ftpauth[ftp->count1]);
        /* remain in this same state */
      }
      else {
        result = ftp_state_user(conn);
        if(result)
          return result;
      }
      break;

    case FTP_USER:
    case FTP_PASS:
      result = ftp_state_user_resp(conn, ftpcode, ftp->state);
      break;

    case FTP_ACCT:
      result = ftp_state_acct_resp(conn, ftpcode);
      break;

    case FTP_PBSZ:
      /* FIX: check response code */

      /* For TLS, the data connection can have one of two security levels.

      1) Clear (requested by 'PROT C')

      2)Private (requested by 'PROT P')
      */
      if(!conn->ssl[SECONDARYSOCKET].use) {
        NBFTPSENDF(conn, "PROT %c", 'P');
        state(conn, FTP_PROT);
      }
      else {
        result = ftp_state_pwd(conn);
        if(result)
          return result;
      }

      break;

    case FTP_PROT:
      if(ftpcode/100 == 2)
        /* We have enabled SSL for the data connection! */
        conn->ssl[SECONDARYSOCKET].use = TRUE;
      /* FTP servers typically responds with 500 if they decide to reject
         our 'P' request */
      else if(data->set.ftp_ssl> CURLFTPSSL_CONTROL)
        /* we failed and bails out */
        return CURLE_FTP_SSL_FAILED;

      result = ftp_state_pwd(conn);
      if(result)
        return result;
      break;

    case FTP_PWD:
      if(ftpcode == 257) {
        char *dir = (char *)malloc(nread+1);
        char *store=dir;
        char *ptr=&data->state.buffer[4];  /* start on the first letter */

        if(!dir)
          return CURLE_OUT_OF_MEMORY;

        /* Reply format is like
           257<space>"<directory-name>"<space><commentary> and the RFC959
           says

           The directory name can contain any character; embedded
           double-quotes should be escaped by double-quotes (the
           "quote-doubling" convention).
        */
        if('\"' == *ptr) {
          /* it started good */
          ptr++;
          while(ptr && *ptr) {
            if('\"' == *ptr) {
              if('\"' == ptr[1]) {
                /* "quote-doubling" */
                *store = ptr[1];
                ptr++;
              }
              else {
                /* end of path */
                *store = '\0'; /* zero terminate */
                break; /* get out of this loop */
              }
            }
            else
              *store = *ptr;
            store++;
            ptr++;
          }
          ftp->entrypath =dir; /* remember this */
          infof(data, "Entry path is '%s'\n", ftp->entrypath);
        }
        else {
          /* couldn't get the path */
          free(dir);
          infof(data, "Failed to figure out path\n");
        }
      }
      state(conn, FTP_STOP); /* we are done with the CONNECT phase! */
      infof(data, "protocol connect phase DONE\n");
      break;

    case FTP_QUOTE:
    case FTP_POSTQUOTE:
    case FTP_RETR_PREQUOTE:
    case FTP_STOR_PREQUOTE:
      if(ftpcode >= 400) {
        failf(conn->data, "QUOT command failed with %03d", ftpcode);
        return CURLE_FTP_QUOTE_ERROR;
      }
      result = ftp_state_quote(conn, FALSE, ftp->state);
      if(result)
        return result;

      break;

    case FTP_CWD:
      if(ftpcode/100 != 2) {
        /* failure to CWD there */
        if(conn->data->set.ftp_create_missing_dirs &&
           ftp->count1 && !ftp->count2) {
          /* try making it */
          ftp->count2++; /* counter to prevent CWD-MKD loops */
          NBFTPSENDF(conn, "MKD %s", ftp->dirs[ftp->count1 - 1]);
          state(conn, FTP_MKD);
        }
        else
          /* return failure */
          return CURLE_FTP_ACCESS_DENIED;
      }
      else {
        /* success */
        ftp->count2=0;
        if(++ftp->count1 <= ftp->dirdepth) {
          /* send next CWD */
          NBFTPSENDF(conn, "CWD %s", ftp->dirs[ftp->count1 - 1]);
        }
        else {
          result = ftp_state_post_cwd(conn);
          if(result)
            return result;
        }
      }
      break;

    case FTP_MKD:
      if(ftpcode/100 != 2) {
        /* failure to MKD the dir */
        failf(data, "Failed to MKD dir: %03d", ftpcode);
        return CURLE_FTP_ACCESS_DENIED;
      }
      state(conn, FTP_CWD);
      /* send CWD */
      NBFTPSENDF(conn, "CWD %s", ftp->dirs[ftp->count1 - 1]);
      break;

    case FTP_MDTM:
      result = ftp_state_mdtm_resp(conn, ftpcode);
      break;

    case FTP_TYPE:
    case FTP_LIST_TYPE:
    case FTP_RETR_TYPE:
    case FTP_STOR_TYPE:
      result = ftp_state_type_resp(conn, ftpcode, ftp->state);
      break;

    case FTP_SIZE:
    case FTP_RETR_SIZE:
    case FTP_STOR_SIZE:
      result = ftp_state_size_resp(conn, ftpcode, ftp->state);
      break;

    case FTP_REST:
    case FTP_RETR_REST:
      result = ftp_state_rest_resp(conn, ftpcode, ftp->state);
      break;

    case FTP_PASV:
      result = ftp_state_pasv_resp(conn, ftpcode);
      break;

    case FTP_PORT:
      result = ftp_state_port_resp(conn, ftpcode);
      break;

    case FTP_LIST:
    case FTP_RETR:
      result = ftp_state_get_resp(conn, ftpcode, ftp->state);
      break;

    case FTP_STOR:
      result = ftp_state_stor_resp(conn, ftpcode);
      break;

    case FTP_QUIT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      state(conn, FTP_STOP);
      break;
    }
  } /* if(ftpcode) */

  return result;
}

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
static long ftp_state_timeout(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  struct FTP *ftp = conn->proto.ftp;
  long timeout_ms=360000; /* in milliseconds */

  if(data->set.ftp_response_timeout )
    /* if CURLOPT_FTP_RESPONSE_TIMEOUT is set, use that to determine remaining
       time.  Also, use ftp->response because FTP_RESPONSE_TIMEOUT is supposed
       to govern the response for any given ftp response, not for the time
       from connect to the given ftp response. */
    timeout_ms = data->set.ftp_response_timeout*1000 - /* timeout time */
      Curl_tvdiff(Curl_tvnow(), ftp->response); /* spent time */
  else if(data->set.timeout)
    /* if timeout is requested, find out how much remaining time we have */
    timeout_ms = data->set.timeout*1000 - /* timeout time */
      Curl_tvdiff(Curl_tvnow(), conn->now); /* spent time */
  else
    /* Without a requested timeout, we only wait 'response_time' seconds for
       the full response to arrive before we bail out */
    timeout_ms = ftp->response_time*1000 -
      Curl_tvdiff(Curl_tvnow(), ftp->response); /* spent time */

  return timeout_ms;
}


/* called repeatedly until done from multi.c */
CURLcode Curl_ftp_multi_statemach(struct connectdata *conn,
                                  bool *done)
{
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  struct SessionHandle *data=conn->data;
  struct FTP *ftp = conn->proto.ftp;
  CURLcode result = CURLE_OK;
  long timeout_ms = ftp_state_timeout(conn);

  *done = FALSE; /* default to not done yet */

  if(timeout_ms <= 0) {
    failf(data, "FTP response timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  rc = Curl_select(ftp->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                   ftp->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                   0);

  if(rc == -1) {
    failf(data, "select error");
    return CURLE_OUT_OF_MEMORY;
  }
  else if(rc != 0) {
    result = ftp_statemach_act(conn);
    *done = (ftp->state == FTP_STOP);
  }
  /* if rc == 0, then select() timed out */

  return result;
}

static CURLcode ftp_easy_statemach(struct connectdata *conn)
{
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  struct SessionHandle *data=conn->data;
  struct FTP *ftp = conn->proto.ftp;
  CURLcode result = CURLE_OK;

  while(ftp->state != FTP_STOP) {
    long timeout_ms = ftp_state_timeout(conn);

    if(timeout_ms <=0 ) {
      failf(data, "FTP response timeout");
      return CURLE_OPERATION_TIMEDOUT; /* already too little time */
    }

    rc = Curl_select(ftp->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                     ftp->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                     timeout_ms);

    if(rc == -1) {
      failf(data, "select error");
      return CURLE_OUT_OF_MEMORY;
    }
    else if(rc == 0) {
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    else {
      result = ftp_statemach_act(conn);
      if(result)
        break;
    }
  }

  return result;
}

/*
 * Curl_ftp_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE is not. When called as
 * a part of the easy interface, it will always be TRUE.
 */
CURLcode Curl_ftp_connect(struct connectdata *conn,
                          bool *done) /* see description above */
{
  struct FTP *ftp;
  CURLcode result;

  *done = FALSE; /* default to not done yet */

  ftp = (struct FTP *)calloc(sizeof(struct FTP), 1);
  if(!ftp)
    return CURLE_OUT_OF_MEMORY;

  conn->proto.ftp = ftp;

  /* We always support persistant connections on ftp */
  conn->bits.close = FALSE;

  /* get some initial data into the ftp struct */
  ftp->bytecountp = &conn->bytecount;

  /* no need to duplicate them, this connectdata struct won't change */
  ftp->user = conn->user;
  ftp->passwd = conn->passwd;
  if (isBadFtpString(ftp->user) || isBadFtpString(ftp->passwd))
    return CURLE_URL_MALFORMAT;

  ftp->response_time = 3600; /* set default response time-out */

#ifndef CURL_DISABLE_HTTP
  if (conn->bits.tunnel_proxy) {
    /* BLOCKING */
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = Curl_ConnectHTTPProxyTunnel(conn, FIRSTSOCKET,
                                         conn->host.name, conn->remote_port);
    if(CURLE_OK != result)
      return result;
  }
#endif   /* CURL_DISABLE_HTTP */

  if(conn->protocol & PROT_FTPS) {
    /* BLOCKING */
    /* FTPS is simply ftp with SSL for the control channel */
    /* now, perform the SSL initialization for this socket */
    result = Curl_SSLConnect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  /* When we connect, we start in the state where we await the 220
     response */
  state(conn, FTP_WAIT220);
  ftp->response = Curl_tvnow(); /* start response time-out now! */

  if(conn->data->state.used_interface == Curl_if_multi)
    result = Curl_ftp_multi_statemach(conn, done);
  else {
    result = ftp_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}

/***********************************************************************
 *
 * Curl_ftp_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
CURLcode Curl_ftp_done(struct connectdata *conn, CURLcode status)
{
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;
  ssize_t nread;
  int ftpcode;
  CURLcode result=CURLE_OK;
  bool was_ctl_valid = ftp->ctl_valid;
  size_t flen;
  size_t dlen;
  char *path;

  /* now store a copy of the directory we are in */
  if(ftp->prevpath)
    free(ftp->prevpath);

  path = curl_unescape(conn->path, 0); /* get the "raw" path */
  if(!path)
    return CURLE_OUT_OF_MEMORY;

  flen = ftp->file?strlen(ftp->file):0; /* file is "raw" already */
  dlen = strlen(path)-flen;
  if(dlen) {
    ftp->prevpath = path;
    if(flen)
      /* if 'path' is not the whole string */
      ftp->prevpath[dlen]=0; /* terminate */
    infof(data, "Remembering we are in dir %s\n", ftp->prevpath);
  }
  else {
    ftp->prevpath = NULL; /* no path */
    free(path);
  }
  /* free the dir tree and file parts */
  freedirs(ftp);

  ftp->ctl_valid = FALSE;

  if(data->set.upload) {
    if((-1 != data->set.infilesize) &&
       (data->set.infilesize != *ftp->bytecountp) &&
       !data->set.crlf) {
      failf(data, "Uploaded unaligned file size (%" FORMAT_OFF_T
            " out of %" FORMAT_OFF_T " bytes)",
            *ftp->bytecountp, data->set.infilesize);
      conn->bits.close = TRUE; /* close this connection since we don't
                                  know what state this error leaves us in */
      return CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != conn->size) && (conn->size != *ftp->bytecountp) &&
       (conn->maxdownload != *ftp->bytecountp)) {
      failf(data, "Received only partial file: %" FORMAT_OFF_T " bytes",
            *ftp->bytecountp);
      conn->bits.close = TRUE; /* close this connection since we don't
                                  know what state this error leaves us in */
      return CURLE_PARTIAL_FILE;
    }
    else if(!ftp->dont_check &&
            !*ftp->bytecountp &&
            (conn->size>0)) {
      /* We consider this an error, but there's no true FTP error received
         why we need to continue to "read out" the server response too.
         We don't want to leave a "waiting" server reply if we'll get told
         to make a second request on this same connection! */
      failf(data, "No data was received!");
      result = CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  switch(status) {
  case CURLE_BAD_DOWNLOAD_RESUME:
  case CURLE_FTP_WEIRD_PASV_REPLY:
  case CURLE_FTP_PORT_FAILED:
  case CURLE_FTP_COULDNT_SET_BINARY:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_FTP_ACCESS_DENIED:
    /* the connection stays alive fine even though this happened */
    /* fall-through */
  case CURLE_OK: /* doesn't affect the control connection's status */
    ftp->ctl_valid = was_ctl_valid;
    break;
  default:       /* by default, an error means the control connection is
                    wedged and should not be used anymore */
    ftp->ctl_valid = FALSE;
    break;
  }

#ifdef HAVE_KRB4
  Curl_sec_fflush_fd(conn, conn->sock[SECONDARYSOCKET]);
#endif

  /* shut down the socket to inform the server we're done */

#ifdef _WIN32_WCE
  shutdown(conn->sock[SECONDARYSOCKET],2);  /* SD_BOTH */
#endif

  sclose(conn->sock[SECONDARYSOCKET]);

  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;

  if(!ftp->no_transfer && !status) {
    /* Let's see what the server says about the transfer we just performed,
     * but lower the timeout as sometimes this connection has died while the
     * data has been transfered. This happens when doing through NATs etc that
     * abandon old silent connections.
     */
    ftp->response_time = 60; /* give it only a minute for now */

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);

    ftp->response_time = 3600; /* set this back to one hour waits */

    if(!nread && (CURLE_OPERATION_TIMEDOUT == result)) {
      failf(data, "control connection looks dead");
      return result;
    }

    if(result)
      return result;

    if(!ftp->dont_check) {
      /* 226 Transfer complete, 250 Requested file action okay, completed. */
      if((ftpcode != 226) && (ftpcode != 250)) {
        failf(data, "server did not report OK, got %d", ftpcode);
        return CURLE_FTP_WRITE_ERROR;
      }
    }
  }

  /* clear these for next connection */
  ftp->no_transfer = FALSE;
  ftp->dont_check = FALSE;

  if (!result && conn->sec_conn) {   /* 3rd party transfer */
    /* "done" with the secondary connection */
    result = Curl_ftp_done(conn->sec_conn, status);
  }

  /* Send any post-transfer QUOTE strings? */
  if(!status && !result && data->set.postquote)
    result = ftp_sendquote(conn, data->set.postquote);

  return result;
}

/***********************************************************************
 *
 * ftp_sendquote()
 *
 * Where a 'quote' means a list of custom commands to send to the server.
 * The quote list is passed as an argument.
 */

static
CURLcode ftp_sendquote(struct connectdata *conn, struct curl_slist *quote)
{
  struct curl_slist *item;
  ssize_t nread;
  int ftpcode;
  CURLcode result;

  item = quote;
  while (item) {
    if (item->data) {
      FTPSENDF(conn, "%s", item->data);

      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
      if (result)
        return result;

      if (ftpcode >= 400) {
        failf(conn->data, "QUOT string not accepted: %s", item->data);
        return CURLE_FTP_QUOTE_ERROR;
      }
    }

    item = item->next;
  }

  return CURLE_OK;
}

/***********************************************************************
 *
 * ftp_transfertype()
 *
 * Set transfer type. We only deal with ASCII or BINARY so this function
 * sets one of them.
 */
static CURLcode ftp_transfertype(struct connectdata *conn,
                                  bool ascii)
{
  struct SessionHandle *data = conn->data;
  int ftpcode;
  ssize_t nread;
  CURLcode result;

  FTPSENDF(conn, "TYPE %s", ascii?"A":"I");

  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode != 200) {
    failf(data, "Couldn't set %s mode",
          ascii?"ASCII":"binary");
    return ascii? CURLE_FTP_COULDNT_SET_ASCII:CURLE_FTP_COULDNT_SET_BINARY;
  }

  return CURLE_OK;
}

/***************************************************************************
 *
 * ftp_pasv_verbose()
 *
 * This function only outputs some informationals about this second connection
 * when we've issued a PASV command before and thus we have connected to a
 * possibly new IP address.
 *
 */
static void
ftp_pasv_verbose(struct connectdata *conn,
                 Curl_addrinfo *ai,
                 char *newhost, /* ascii version */
                 int port)
{
  char buf[256];
  Curl_printable_address(ai, buf, sizeof(buf));
  infof(conn->data, "Connecting to %s (%s) port %d\n", newhost, buf, port);
}

/*
  Check if this is a range download, and if so, set the internal variables
  properly.
 */

static CURLcode ftp_range(struct connectdata *conn)
{
  curl_off_t from, to;
  curl_off_t totalsize=-1;
  char *ptr;
  char *ptr2;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;

  if(conn->bits.use_range && conn->range) {
    from=curlx_strtoofft(conn->range, &ptr, 0);
    while(ptr && *ptr && (isspace((int)*ptr) || (*ptr=='-')))
      ptr++;
    to=curlx_strtoofft(ptr, &ptr2, 0);
    if(ptr == ptr2) {
      /* we didn't get any digit */
      to=-1;
    }
    if((-1 == to) && (from>=0)) {
      /* X - */
      conn->resume_from = from;
      infof(data, "FTP RANGE %" FORMAT_OFF_T " to end of file\n", from);
    }
    else if(from < 0) {
      /* -Y */
      totalsize = -from;
      conn->maxdownload = -from;
      conn->resume_from = from;
      infof(data, "FTP RANGE the last %" FORMAT_OFF_T " bytes\n", totalsize);
    }
    else {
      /* X-Y */
      totalsize = to-from;
      conn->maxdownload = totalsize+1; /* include the last mentioned byte */
      conn->resume_from = from;
      infof(data, "FTP RANGE from %" FORMAT_OFF_T
            " getting %" FORMAT_OFF_T " bytes\n", from, conn->maxdownload);
    }
    infof(data, "range-download from %" FORMAT_OFF_T
          " to %" FORMAT_OFF_T ", totally %" FORMAT_OFF_T " bytes\n",
          from, to, conn->maxdownload);
    ftp->dont_check = TRUE; /* dont check for successful transfer */
  }
  return CURLE_OK;
}


/*
 * Curl_ftp_nextconnect()
 *
 * This function shall be called when the second FTP (data) connection is
 * connected.
 */

CURLcode Curl_ftp_nextconnect(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  CURLcode result = CURLE_OK;

  /* the ftp struct is inited in Curl_ftp_connect() */
  struct FTP *ftp = conn->proto.ftp;

  infof(data, "DO-MORE phase starts\n");

  if(!ftp->no_transfer && !conn->bits.no_body) {
    /* a transfer is about to take place */

    if(data->set.upload) {
      NBFTPSENDF(conn, "TYPE %c", data->set.ftp_ascii?'A':'I');
      state(conn, FTP_STOR_TYPE);
    }
    else {
      /* download */
      ftp->downloadsize = -1; /* unknown as of yet */

      result = ftp_range(conn);
      if(result)
        ;
      else if((data->set.ftp_list_only) || !ftp->file) {
        /* The specified path ends with a slash, and therefore we think this
           is a directory that is requested, use LIST. But before that we
           need to set ASCII transfer mode. */
        NBFTPSENDF(conn, "TYPE A", NULL);
        state(conn, FTP_LIST_TYPE);
      }
      else {
        NBFTPSENDF(conn, "TYPE %c", data->set.ftp_ascii?'A':'I');
        state(conn, FTP_RETR_TYPE);
      }
    }
    result = ftp_easy_statemach(conn);
  }

  if(ftp->no_transfer)
    /* no data to transfer. FIX: it feels like a kludge to have this here
       too! */
    result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  /* end of transfer */
  infof(data, "DO-MORE phase ends\n");

  return result;
}



/***********************************************************************
 *
 * ftp_perform()
 *
 * This is the actual DO function for FTP. Get a file/directory according to
 * the options previously setup.
 */

static
CURLcode ftp_perform(struct connectdata *conn,
                     bool *connected,  /* connect status after PASV / PORT */
                     bool *dophase_done)
{
  /* this is FTP and no proxy */
  CURLcode result=CURLE_OK;
  struct SessionHandle *data=conn->data;

  infof(data, "DO phase starts\n");

  *dophase_done = FALSE; /* not done yet */

  /* start the first command in the DO phase */
  result = ftp_state_quote(conn, TRUE, FTP_QUOTE);
  if(result)
    return result;

  /* run the state-machine */
  if(conn->data->state.used_interface == Curl_if_multi)
    result = Curl_ftp_multi_statemach(conn, dophase_done);
  else {
    result = ftp_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect;

  if(*dophase_done)
    infof(data, "DO phase is comlete\n");

  return result;
}

/***********************************************************************
 *
 * Curl_ftp()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (ftp_perform).
 *
 * The input argument is already checked for validity.
 */
CURLcode Curl_ftp(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; /* default to false */

  retcode = ftp_parse_url_path(conn);
  if (retcode)
    return retcode;

  if (conn->sec_conn) {
    /* 3rd party transfer */
    *done = TRUE; /* BLOCKING */
    retcode = ftp_3rdparty(conn);
  }
  else
    retcode = ftp_regular_transfer(conn, done);

  return retcode;
}

/***********************************************************************
 *
 * Curl_(nb)ftpsendf()
 *
 * Sends the formated string as a ftp command to a ftp server
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 * The "nb" version is made to Never Block.
 */
CURLcode Curl_nbftpsendf(struct connectdata *conn,
                       const char *fmt, ...)
{
  ssize_t bytes_written;
  char s[256];
  size_t write_len;
  char *sptr=s;
  CURLcode res = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;
  struct SessionHandle *data = conn->data;

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(s, 250, fmt, ap);
  va_end(ap);

  strcat(s, "\r\n"); /* append a trailing CRLF */

  bytes_written=0;
  write_len = strlen(s);

  res = Curl_write(conn, conn->sock[FIRSTSOCKET], sptr, write_len,
                   &bytes_written);

  if(CURLE_OK != res)
    return res;

  if(conn->data->set.verbose)
    Curl_debug(conn->data, CURLINFO_HEADER_OUT, sptr, bytes_written,
               conn);

  if(bytes_written != (ssize_t)write_len) {
    /* the whole chunk was not sent, store the rest of the data */
    write_len -= bytes_written;
    sptr += bytes_written;
    ftp->sendthis = malloc(write_len);
    if(ftp->sendthis) {
      memcpy(ftp->sendthis, sptr, write_len);
      ftp->sendsize=ftp->sendleft=write_len;
    }
    else {
      failf(data, "out of memory");
      res = CURLE_OUT_OF_MEMORY;
    }
  }
  else
    ftp->response = Curl_tvnow();

  return res;
}

CURLcode Curl_ftpsendf(struct connectdata *conn,
                       const char *fmt, ...)
{
  ssize_t bytes_written;
  char s[256];
  size_t write_len;
  char *sptr=s;
  CURLcode res = CURLE_OK;

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(s, 250, fmt, ap);
  va_end(ap);

  strcat(s, "\r\n"); /* append a trailing CRLF */

  bytes_written=0;
  write_len = strlen(s);

  while(1) {
    res = Curl_write(conn, conn->sock[FIRSTSOCKET], sptr, write_len,
                     &bytes_written);

    if(CURLE_OK != res)
      break;

    if(conn->data->set.verbose)
      Curl_debug(conn->data, CURLINFO_HEADER_OUT, sptr, bytes_written, conn);

    if(bytes_written != (ssize_t)write_len) {
      write_len -= bytes_written;
      sptr += bytes_written;
    }
    else
      break;
  }

  return res;
}

/***********************************************************************
 *
 * ftp_quit()
 *
 * This should be called before calling sclose() on an ftp control connection
 * (not data connections). We should then wait for the response from the
 * server before returning. The calling code should then try to close the
 * connection.
 *
 */
static CURLcode ftp_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->proto.ftp->ctl_valid) {
    NBFTPSENDF(conn, "QUIT", NULL);
    state(conn, FTP_QUIT);

    result = ftp_easy_statemach(conn);
  }

  return result;
}

/***********************************************************************
 *
 * Curl_ftp_disconnect()
 *
 * Disconnect from an FTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
CURLcode Curl_ftp_disconnect(struct connectdata *conn)
{
  struct FTP *ftp= conn->proto.ftp;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to.

     ftp_quit() will check the state of ftp->ctl_valid. If it's ok it
     will try to send the QUIT command, otherwise it will just return.
  */

  /* The FTP session may or may not have been allocated/setup at this point! */
  if(ftp) {
    (void)ftp_quit(conn); /* ignore errors on the QUIT */

    if(ftp->entrypath)
      free(ftp->entrypath);
    if(ftp->cache) {
      free(ftp->cache);
      ftp->cache = NULL;
    }
    freedirs(ftp);
    if(ftp->prevpath) {
      free(ftp->prevpath);
      ftp->prevpath = NULL;
    }
  }
  return CURLE_OK;
}

/***********************************************************************
 *
 * ftp_mkd()
 *
 * Makes a directory on the FTP server.
 *
 * Calls failf()
 */
static CURLcode ftp_mkd(struct connectdata *conn, char *path)
{
  CURLcode result=CURLE_OK;
  int ftpcode; /* for ftp status */
  ssize_t nread;

  /* Create a directory on the remote server */
  FTPSENDF(conn, "MKD %s", path);

  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  switch(ftpcode) {
  case 257:
    /* success! */
    infof( conn->data , "Created remote directory %s\n" , path );
    break;
  case 550:
    failf(conn->data, "Permission denied to make directory %s", path);
    result = CURLE_FTP_ACCESS_DENIED;
    break;
  default:
    failf(conn->data, "unrecognized MKD response: %d", ftpcode );
    result = CURLE_FTP_ACCESS_DENIED;
    break;
  }
  return  result;
}

/***********************************************************************
 *
 * ftp_cwd()
 *
 * Send 'CWD' to the remote server to Change Working Directory.  It is the ftp
 * version of the unix 'cd' command. This function is only called from the
 * ftp_cwd_and_mkd() function these days.
 *
 * This function does NOT call failf().
 */
static
CURLcode ftp_cwd(struct connectdata *conn, char *path)
{
  ssize_t nread;
  int     ftpcode;
  CURLcode result;

  FTPSENDF(conn, "CWD %s", path);
  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if (!result) {
    /* According to RFC959, CWD is supposed to return 250 on success, but
       there seem to be non-compliant FTP servers out there that return 200,
       so we accept any '2xy' code here. */
    if (ftpcode/100 != 2)
      result = CURLE_FTP_ACCESS_DENIED;
  }

  return result;
}

/***********************************************************************
 *
 * ftp_cwd_and_mkd()
 *
 * Change to the given directory.  If the directory is not present, and we
 * have been told to allow it, then create the directory and cd to it.
 *
 */
static CURLcode ftp_cwd_and_mkd(struct connectdata *conn, char *path)
{
  CURLcode result;

  result = ftp_cwd(conn, path);
  if (result) {
    if(conn->data->set.ftp_create_missing_dirs) {
      result = ftp_mkd(conn, path);
      if (result)
        /* ftp_mkd() calls failf() itself */
        return result;
      result = ftp_cwd(conn, path);
    }
    if(result)
      failf(conn->data, "Couldn't CWD to %s", path);
  }
  return result;
}



/***********************************************************************
 *
 * ftp_3rdparty_pretransfer()
 *
 * Preparation for 3rd party transfer.
 *
 */
static CURLcode ftp_3rdparty_pretransfer(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct connectdata *sec_conn = conn->sec_conn;

  conn->xfertype = TARGET3RD;
  sec_conn->xfertype = SOURCE3RD;

  /* sets transfer type */
  result = ftp_transfertype(conn, data->set.ftp_ascii);
  if (result)
    return result;

  result = ftp_transfertype(sec_conn, data->set.ftp_ascii);
  if (result)
    return result;

  /* Send any PREQUOTE strings after transfer type is set? */
  if (data->set.source_prequote) {
    /* sends command(s) to source server before file transfer */
    result = ftp_sendquote(sec_conn, data->set.source_prequote);
  }
  if (!result && data->set.prequote)
    result = ftp_sendquote(conn, data->set.prequote);

  return result;
}



/***********************************************************************
 *
 * ftp_3rdparty_transfer()
 *
 * Performs 3rd party transfer.
 *
 */
static CURLcode ftp_3rdparty_transfer(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  ssize_t nread;
  int ftpcode, ip[4], port[2];
  struct SessionHandle *data = conn->data;
  struct connectdata *sec_conn = conn->sec_conn;
  char *buf = data->state.buffer;   /* this is our buffer */
  char *str = buf;
  char pasv_port[50];
  const char *stor_cmd;
  struct connectdata *pasv_conn;
  struct connectdata *port_conn;

  if (data->set.ftpport == NULL) {
    pasv_conn = conn;
    port_conn = sec_conn;
  }
  else {
    pasv_conn = sec_conn;
    port_conn = conn;
  }

  result = ftp_cwd_and_create_path(conn);
  if (result)
    return result;

  /* sets the passive mode */
  FTPSENDF(pasv_conn, "%s", "PASV");
  result = Curl_GetFTPResponse(&nread, pasv_conn, &ftpcode);
  if (result)
    return result;

  if (ftpcode != 227) {
    failf(data, "Odd return code after PASV: %03d", ftpcode);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

  while (*str) {
    if (6 == sscanf(str, "%d,%d,%d,%d,%d,%d",
                    &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]))
      break;
    str++;
  }

  if (!*str) {
    failf(pasv_conn->data, "Couldn't interpret the 227-reply");
    return CURLE_FTP_WEIRD_227_FORMAT;
  }

  snprintf(pasv_port, sizeof(pasv_port), "%d,%d,%d,%d,%d,%d", ip[0], ip[1],
           ip[2], ip[3], port[0], port[1]);

  /* sets data connection between remote hosts */
  FTPSENDF(port_conn, "PORT %s", pasv_port);
  result = Curl_GetFTPResponse(&nread, port_conn, &ftpcode);
  if (result)
    return result;

  if (ftpcode != 200) {
    failf(data, "PORT command attempts failed: %03d", ftpcode);
    return CURLE_FTP_PORT_FAILED;
  }

  /* we might append onto the file instead of overwriting it */
  stor_cmd = data->set.ftp_append?"APPE":"STOR";

  /* transfers file between remote hosts */
  /* FIX: this should send a series of CWD commands and then RETR only the
     ftp->file file. The conn->path "full path" is not unescaped. Test case
     230 tests this. */
  FTPSENDF(sec_conn, "RETR %s", sec_conn->path);

  if(!data->set.ftpport) {

    result = Curl_GetFTPResponse(&nread, sec_conn, &ftpcode);
    if (result)
      return result;

    if((ftpcode != 150) && (ftpcode != 125)) {
      failf(data, "Failed RETR: %03d", ftpcode);
      return CURLE_FTP_COULDNT_RETR_FILE;
    }

    result = Curl_ftpsendf(conn, "%s %s", stor_cmd, conn->proto.ftp->file);
    if(CURLE_OK == result)
      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode >= 400) {
      failf(data, "Failed FTP upload: %03d", ftpcode);
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

  }
  else {

    result = Curl_ftpsendf(conn, "%s %s", stor_cmd, conn->proto.ftp->file);
    if(CURLE_OK == result)
      result = Curl_GetFTPResponse(&nread, sec_conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode >= 400) {
      failf(data, "Failed FTP upload: %03d", ftpcode);
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if (result)
      return result;

    if((ftpcode != 150) && (ftpcode != 125)) {
      failf(data, "Failed FTP upload: %03d", ftpcode);
      return CURLE_FTP_COULDNT_STOR_FILE;
    }
  }

  return CURLE_OK;
}



/***********************************************************************
 *
 * ftp_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static
CURLcode ftp_parse_url_path(struct connectdata *conn)
{
  CURLcode retcode = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp;
  size_t dlen;

  char *slash_pos;  /* position of the first '/' char in curpos */
  char *cur_pos = conn->path; /* current position in path. point at the begin
                                 of next path component */

  /* the ftp struct is already inited in ftp_connect() */
  ftp = conn->proto.ftp;
  ftp->ctl_valid = FALSE;

  ftp->dirdepth = 0;
  ftp->diralloc = 5; /* default dir depth to allocate */
  ftp->dirs = (char **)calloc(ftp->diralloc, sizeof(ftp->dirs[0]));
  if(!ftp->dirs)
    return CURLE_OUT_OF_MEMORY;

  /* parse the URL path into separate path components */
  while((slash_pos=strchr(cur_pos, '/'))) {
    /* 1 or 0 to indicate absolute directory */
    bool absolute_dir = (cur_pos - conn->path > 0) && (ftp->dirdepth == 0);

    /* seek out the next path component */
    if (slash_pos-cur_pos) {
      /* we skip empty path components, like "x//y" since the FTP command CWD
         requires a parameter and a non-existant parameter a) doesn't work on
         many servers and b) has no effect on the others. */
      int len = (int)(slash_pos - cur_pos + absolute_dir);
      ftp->dirs[ftp->dirdepth] = curl_unescape(cur_pos - absolute_dir, len);

      if (!ftp->dirs[ftp->dirdepth]) { /* run out of memory ... */
        failf(data, "no memory");
        freedirs(ftp);
        return CURLE_OUT_OF_MEMORY;
      }
      if (isBadFtpString(ftp->dirs[ftp->dirdepth])) {
        freedirs(ftp);
        return CURLE_URL_MALFORMAT;
      }
    }
    else {
      cur_pos = slash_pos + 1; /* jump to the rest of the string */
      continue;
    }

    if(!retcode) {
      cur_pos = slash_pos + 1; /* jump to the rest of the string */
      if(++ftp->dirdepth >= ftp->diralloc) {
        /* enlarge array */
        char *bigger;
        ftp->diralloc *= 2; /* double the size each time */
        bigger = realloc(ftp->dirs, ftp->diralloc * sizeof(ftp->dirs[0]));
        if(!bigger) {
          ftp->dirdepth--;
          freedirs(ftp);
          return CURLE_OUT_OF_MEMORY;
        }
        ftp->dirs = (char **)bigger;
      }
    }
  }

  ftp->file = cur_pos;  /* the rest is the file name */

  if(*ftp->file) {
    ftp->file = curl_unescape(ftp->file, 0);
    if(NULL == ftp->file) {
      freedirs(ftp);
      failf(data, "no memory");
      return CURLE_OUT_OF_MEMORY;
    }
    if (isBadFtpString(ftp->file)) {
      freedirs(ftp);
      return CURLE_URL_MALFORMAT;
    }
  }
  else
    ftp->file=NULL; /* instead of point to a zero byte, we make it a NULL
                       pointer */

  ftp->cwddone = FALSE; /* default to not done */

  if(ftp->prevpath) {
    /* prevpath is "raw" so we convert the input path before we compare the
       strings */
    char *path = curl_unescape(conn->path, 0);
    if(!path)
      return CURLE_OUT_OF_MEMORY;

    dlen = strlen(path) - (ftp->file?strlen(ftp->file):0);
    if((dlen == strlen(ftp->prevpath)) &&
       curl_strnequal(path, ftp->prevpath, dlen)) {
      infof(data, "Request has same path as previous transfer\n");
      ftp->cwddone = TRUE;
    }
    free(path);
  }

  return retcode;
}



/***********************************************************************
 *
 * ftp_cwd_and_create_path()
 *
 * Creates full path on remote target host.
 *
 */
static
CURLcode ftp_cwd_and_create_path(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  /* the ftp struct is already inited in Curl_ftp_connect() */
  struct FTP *ftp = conn->proto.ftp;
  int i;

  if(ftp->cwddone)
    /* already done and fine */
    return CURLE_OK;

  /* This is a re-used connection. Since we change directory to where the
     transfer is taking place, we must now get back to the original dir
     where we ended up after login: */
  if (conn->bits.reuse && ftp->entrypath) {
    if ((result = ftp_cwd_and_mkd(conn, ftp->entrypath)) != CURLE_OK)
      return result;
  }

  for (i=0; i < ftp->dirdepth; i++) {
    /* RFC 1738 says empty components should be respected too, but
       that is plain stupid since CWD can't be used with an empty argument */
    if ((result = ftp_cwd_and_mkd(conn, ftp->dirs[i])) != CURLE_OK)
      return result;
  }

  return result;
}

/* call this when the DO phase has completed */
static CURLcode ftp_dophase_done(struct connectdata *conn,
                                 bool connected)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->proto.ftp;

  if(connected)
    result = Curl_ftp_nextconnect(conn);

  if(result && (conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD)) {
    /* Failure detected, close the second socket if it was created already */
    sclose(conn->sock[SECONDARYSOCKET]);
    conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
  }

  if(ftp->no_transfer)
    /* no data to transfer */
    result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  else if(!connected)
    /* since we didn't connect now, we want do_more to get called */
    conn->bits.do_more = TRUE;

  ftp->ctl_valid = TRUE; /* seems good */

  return result;
}

/* called from multi.c while DOing */
CURLcode Curl_ftp_doing(struct connectdata *conn,
                        bool *dophase_done)
{
  CURLcode result;
  result = Curl_ftp_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = ftp_dophase_done(conn, FALSE /* not connected */);

    infof(conn->data, "DO phase is comlete\n");
  }
  return result;
}

/***********************************************************************
 *
 * ftp_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 *
 * ftp->ctl_valid starts out as FALSE, and gets set to TRUE if we reach the
 * Curl_ftp_done() function without finding any major problem.
 */
static
CURLcode ftp_regular_transfer(struct connectdata *conn,
                              bool *dophase_done)
{
  CURLcode result=CURLE_OK;
  bool connected=0;
  struct SessionHandle *data = conn->data;
  struct FTP *ftp;

  /* the ftp struct is already inited in ftp_connect() */
  ftp = conn->proto.ftp;
  conn->size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  ftp->ctl_valid = TRUE; /* starts good */

  result = ftp_perform(conn,
                       &connected, /* have we connected after PASV/PORT */
                       dophase_done); /* all commands in the DO-phase done? */

  if(CURLE_OK == result) {

    if(!*dophase_done)
      /* the DO phase has not completed yet */
      return CURLE_OK;

    result = ftp_dophase_done(conn, connected);
    if(result)
      return result;
  }
  else
    freedirs(ftp);

  return result;
}



/***********************************************************************
 *
 * ftp_3rdparty()
 *
 * The input argument is already checked for validity.
 * Performs a 3rd party transfer between two remote hosts.
 */
static CURLcode ftp_3rdparty(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  conn->proto.ftp->ctl_valid = conn->sec_conn->proto.ftp->ctl_valid = TRUE;
  conn->size = conn->sec_conn->size = -1;

  result = ftp_3rdparty_pretransfer(conn);
  if (!result)
    result = ftp_3rdparty_transfer(conn);

  return result;
}

#endif /* CURL_DISABLE_FTP */
