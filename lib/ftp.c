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
#include "security.h"
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
static CURLcode ftp_regular_transfer(struct connectdata *conn);
static CURLcode ftp_3rdparty(struct connectdata *conn);

/* easy-to-use macro: */
#define FTPSENDF(x,y,z) if((result = Curl_ftpsendf(x,y,z))) return result

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
  /* Brand new implementation.
   * We cannot read just one byte per read() and then go back to select()
   * as it seems that the OpenSSL read() stuff doesn't grok that properly.
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
              Curl_debug(data, CURLINFO_HEADER_IN, line_start, perline, conn->host.dispname);

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

/*
 * Curl_ftp_connect() should do everything that is to be considered a part of
 * the connection phase.
 */
CURLcode Curl_ftp_connect(struct connectdata *conn)
{
  /* this is FTP and no proxy */
  ssize_t nread;
  struct SessionHandle *data=conn->data;
  char *buf = data->state.buffer; /* this is our buffer */
  struct FTP *ftp;
  CURLcode result;
  int ftpcode, trynum;
  static const char * const ftpauth[]  = {
    "SSL", "TLS", NULL
  };

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
  ftp->response_time = 3600; /* set default response time-out */

#ifndef CURL_DISABLE_HTTP
  if (conn->bits.tunnel_proxy) {
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = Curl_ConnectHTTPProxyTunnel(conn, FIRSTSOCKET,
                                         conn->host.name, conn->remote_port);
    if(CURLE_OK != result)
      return result;
  }
#endif   /* CURL_DISABLE_HTTP */

  if(conn->protocol & PROT_FTPS) {
    /* FTPS is simply ftp with SSL for the control channel */
    /* now, perform the SSL initialization for this socket */
    result = Curl_SSLConnect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  /* The first thing we do is wait for the "220*" line: */
  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode != 220) {
    failf(data, "This doesn't seem like a nice ftp-server response");
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }

#ifdef HAVE_KRB4
  /* if not anonymous login, try a secure login */
  if(data->set.krb4) {

    /* request data protection level (default is 'clear') */
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
    /* we don't have a SSL/TLS connection, try a FTPS connection now */
    int start;
    int trynext;
    int count=0;

    switch(data->set.ftpsslauth) {
    case CURLFTPAUTH_DEFAULT:
    case CURLFTPAUTH_SSL:
      start = 0;
      trynext = 1;
      break;
    case CURLFTPAUTH_TLS:
      start = 1;
      trynext = 0;
      break;
    default:
      failf(data, "unsupported parameter to CURLOPT_FTPSSLAUTH: %d\n",
            data->set.ftpsslauth);
      return CURLE_FAILED_INIT; /* we don't know what to do */
    }

    for (trynum = start; ftpauth[count]; trynum=trynext, count++) {

      FTPSENDF(conn, "AUTH %s", ftpauth[trynum]);

      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);

      if(result)
        return result;

      /* RFC2228 (page 5) says:
       *
       * If the server is willing to accept the named security mechanism, and
       * does not require any security data, it must respond with reply code
       * 234/334.
       */

      if((ftpcode == 234) || (ftpcode == 334)) {
        result = Curl_SSLConnect(conn, FIRSTSOCKET);
        if(result)
          return result;
        conn->protocol |= PROT_FTPS;
        conn->ssl[SECONDARYSOCKET].use = FALSE; /* clear-text data */
        break;
      }
    }
  }

  /* send USER */
  FTPSENDF(conn, "USER %s", ftp->user?ftp->user:"");

  /* wait for feedback */
  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode == 530) {
    /* 530 User ... access denied
       (the server denies to log the specified user) */
    failf(data, "Access denied: %s", &buf[4]);
    return CURLE_FTP_ACCESS_DENIED;
  }
  else if(ftpcode == 331) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    FTPSENDF(conn, "PASS %s", ftp->passwd?ftp->passwd:"");
    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;

    if(ftpcode == 530) {
      /* 530 Login incorrect.
         (the username and/or the password are incorrect)
      or
         530 Sorry, the maximum number of allowed users are already connected
      */
      failf(data, "not logged in: %s", &buf[4]);
      return CURLE_FTP_USER_PASSWORD_INCORRECT;
    }
    else if(ftpcode/100 == 2) {
      /* 230 User ... logged in.
         (user successfully logged in)

         Apparently, proftpd with SSL returns 232 here at times. */

      infof(data, "We have successfully logged in\n");
    }
    else {
      failf(data, "Odd return code after PASS");
      return CURLE_FTP_WEIRD_PASS_REPLY;
    }
  }
  else if(buf[0] == '2') {
    /* 230 User ... logged in.
       (the user logged in without password) */
    infof(data, "We have successfully logged in\n");
    if (conn->ssl[FIRSTSOCKET].use) {
#ifdef HAVE_KRB4
      /* We are logged in with Kerberos, now set the requested protection
       * level
       */
      if(conn->sec_complete)
        Curl_sec_set_protection_level(conn);

      /* We may need to issue a KAUTH here to have access to the files
       * do it if user supplied a password
       */
      if(conn->passwd && *conn->passwd) {
        result = Curl_krb_kauth(conn);
        if(result)
          return result;
      }
#endif
    }
  }
  else {
    failf(data, "Odd return code after USER");
    return CURLE_FTP_WEIRD_USER_REPLY;
  }

  if(conn->ssl[FIRSTSOCKET].use) {
    /* PBSZ = PROTECTION BUFFER SIZE.

       The 'draft-murray-auth-ftp-ssl' (draft 12, page 7) says:

       Specifically, the PROT command MUST be preceded by a PBSZ command
       and a PBSZ command MUST be preceded by a successful security data
       exchange (the TLS negotiation in this case)

       ... (and on page 8):

       Thus the PBSZ command must still be issued, but must have a parameter
       of '0' to indicate that no buffering is taking place and the data
       connection should not be encapsulated.
    */
    FTPSENDF(conn, "PBSZ %d", 0);
    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;

    /* For TLS, the data connection can have one of two security levels.

       1)Clear (requested by 'PROT C')

       2)Private (requested by 'PROT P')
    */
    if(!conn->ssl[SECONDARYSOCKET].use) {
      FTPSENDF(conn, "PROT %c", 'P');
      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
      if(result)
        return result;

      if(ftpcode/100 == 2)
        /* We have enabled SSL for the data connection! */
        conn->ssl[SECONDARYSOCKET].use = TRUE;
      /* FTP servers typically responds with 500 if they decide to reject
         our 'P' request */
      else if(data->set.ftp_ssl> CURLFTPSSL_CONTROL)
        /* we failed and bails out */
        return CURLE_FTP_SSL_FAILED;
    }
  }

  /* send PWD to discover our entry point */
  FTPSENDF(conn, "PWD", NULL);

  /* wait for feedback */
  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode == 257) {
    char *dir = (char *)malloc(nread+1);
    char *store=dir;
    char *ptr=&buf[4]; /* start on the first letter */

    if(!dir)
      return CURLE_OUT_OF_MEMORY;

    /* Reply format is like
       257<space>"<directory-name>"<space><commentary> and the RFC959 says

       The directory name can contain any character; embedded double-quotes
       should be escaped by double-quotes (the "quote-doubling" convention).
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
  else {
    /* We couldn't read the PWD response! */
  }

  return CURLE_OK;
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

  /* now store a copy of the directory we are in */
  if(ftp->prevpath)
    free(ftp->prevpath);

  flen = ftp->file?strlen(ftp->file):0;
  dlen = conn->path?strlen(conn->path)-flen:0;
  if(dlen) {
    ftp->prevpath = malloc(dlen + 1);
    if(!ftp->prevpath)
      return CURLE_OUT_OF_MEMORY;
    memcpy(ftp->prevpath, conn->path, dlen);
    ftp->prevpath[dlen]=0; /* terminate */
    infof(data, "Remembering we are in dir %s\n", ftp->prevpath);
  }
  else
    ftp->prevpath = NULL; /* no path */

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
 * ftp_getfiletime()
 *
 * Get the timestamp of the given file.
 */
static
CURLcode ftp_getfiletime(struct connectdata *conn, char *file)
{
  CURLcode result=CURLE_OK;
  int ftpcode; /* for ftp status */
  ssize_t nread;
  char *buf = conn->data->state.buffer;

  /* we have requested to get the modified-time of the file, this is yet
     again a grey area as the MDTM is not kosher RFC959 */
  FTPSENDF(conn, "MDTM %s", file);

  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  switch(ftpcode) {
  case 213:
    {
      /* we got a time. Format should be: "YYYYMMDDHHMMSS[.sss]" where the
         last .sss part is optional and means fractions of a second */
      int year, month, day, hour, minute, second;
      if(6 == sscanf(buf+4, "%04d%02d%02d%02d%02d%02d",
                     &year, &month, &day, &hour, &minute, &second)) {
        /* we have a time, reformat it */
        time_t secs=time(NULL);
        /* using the good old yacc/bison yuck */
        snprintf(buf, sizeof(conn->data->state.buffer),
                 "%04d%02d%02d %02d:%02d:%02d GMT",
                 year, month, day, hour, minute, second);
        /* now, convert this into a time() value: */
        conn->data->info.filetime = curl_getdate(buf, &secs);
      }
    }
    break;
  default:
    infof(conn->data, "unsupported MDTM reply format\n");
    break;
  case 550: /* "No such file or directory" */
    failf(conn->data, "Given file does not exist");
    result = CURLE_FTP_COULDNT_RETR_FILE;
    break;
  }
  return  result;
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

/***********************************************************************
 *
 * ftp_getsize()
 *
 * Returns the file size (in bytes) of the given remote file.
 */

static
CURLcode ftp_getsize(struct connectdata *conn, char *file,
                     curl_off_t *size)
{
  struct SessionHandle *data = conn->data;
  int ftpcode;
  ssize_t nread;
  char *buf=data->state.buffer;
  CURLcode result;

  FTPSENDF(conn, "SIZE %s", file);
  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode == 213) {
    /* get the size from the ascii string: */
    *size = curlx_strtoofft(buf+4, NULL, 0);
  }
  else
    return CURLE_FTP_COULDNT_GET_SIZE;

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

/***********************************************************************
 *
 * ftp_use_port()
 *
 * Send the proper PORT command. PORT is the ftp client's way of telling the
 * server that *WE* open a port that we listen on an awaits the server to
 * connect to. This is the opposite of PASV.
 */

static
CURLcode ftp_use_port(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  curl_socket_t portsock= CURL_SOCKET_BAD;
  ssize_t nread;
  int ftpcode; /* receive FTP response codes in this */
  CURLcode result;

#ifdef ENABLE_IPV6
  /******************************************************************
   *
   * Here's a piece of IPv6-specific code coming up
   *
   */

  struct addrinfo hints, *res, *ai;
  struct sockaddr_storage ss;
  socklen_t sslen;
  char hbuf[NI_MAXHOST];

  struct sockaddr *sa=(struct sockaddr *)&ss;
  unsigned char *ap;
  unsigned char *pp;
  char portmsgbuf[1024], tmp[1024];

  enum ftpcommand { EPRT, LPRT, PORT, DONE } fcmd;
  const char *mode[] = { "EPRT", "LPRT", "PORT", NULL };
  int rc;
  int error;

  /*
   * we should use Curl_if2ip?  given pickiness of recent ftpd,
   * I believe we should use the same address as the control connection.
   */
  sslen = sizeof(ss);
  rc = getsockname(conn->sock[FIRSTSOCKET], (struct sockaddr *)&ss, &sslen);
  if(rc < 0) {
    failf(data, "getsockname() returned %d\n", rc);
    return CURLE_FTP_PORT_FAILED;
  }

  rc = getnameinfo((struct sockaddr *)&ss, sslen, hbuf, sizeof(hbuf), NULL, 0,
                   NIFLAGS);
  if(rc) {
    failf(data, "getnameinfo() returned %d\n", rc);
    return CURLE_FTP_PORT_FAILED;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = sa->sa_family;
  /*hints.ai_family = ss.ss_family;
    this way can be used if sockaddr_storage is properly defined, as glibc
    2.1.X doesn't do*/
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  rc = getaddrinfo(hbuf, NULL, &hints, &res);
  if(rc) {
    failf(data, "getaddrinfo() returned %d\n", rc);
    return CURLE_FTP_PORT_FAILED;
  }

  portsock = CURL_SOCKET_BAD;
  error = 0;
  for (ai = res; ai; ai = ai->ai_next) {
    /*
     * Workaround for AIX5 getaddrinfo() problem (it doesn't set ai_socktype):
     */
    if (ai->ai_socktype == 0)
      ai->ai_socktype = hints.ai_socktype;

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
  freeaddrinfo(res);
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
  if(!conn->bits.ftp_use_eprt &&
     (conn->ip_addr->ai_family == PF_INET6)) {
    /* EPRT is disabled but we are connected to a IPv6 host, so we ignore the
       request! */
    conn->bits.ftp_use_eprt = TRUE;
  }
#endif


  for (fcmd = EPRT; fcmd != DONE; fcmd++) {
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

      result = Curl_ftpsendf(conn, "%s |%d|%s|%s|", mode[fcmd], eprtaf,
                             portmsgbuf, tmp);
      if(result)
        return result;
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

      result = Curl_ftpsendf(conn, "%s %s", mode[fcmd], portmsgbuf);
      if(result)
        return result;
    }

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;

    if (ftpcode != 200) {
      if (EPRT == fcmd) {
        infof(data, "disabling EPRT usage\n");
        conn->bits.ftp_use_eprt = FALSE;
      }
      else if (LPRT == fcmd) {
        infof(data, "disabling LPRT usage\n");
        conn->bits.ftp_use_lprt = FALSE;
      }
      continue;
    }
    else
      break;
  }

  if (fcmd == DONE) {
    sclose(portsock);
    failf(data, "PORT command attempts failed");
    return CURLE_FTP_PORT_FAILED;
  }
  /* we set the secondary socket variable to this for now, it
     is only so that the cleanup function will close it in case
     we fail before the true secondary stuff is made */
  conn->sock[SECONDARYSOCKET] = portsock;

#else
  /******************************************************************
   *
   * Here's a piece of IPv4-specific code coming up
   *
   */
  struct sockaddr_in sa;
  unsigned short porttouse;
  char myhost[256] = "";
  bool sa_filled_in = FALSE;
  Curl_addrinfo *addr = NULL;
  unsigned short ip[4];

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
          rc = Curl_wait_for_resolv(conn, &h);
        if(h) {
          addr = h->addr;
          /* when we return from this function, we can forget about this entry
             to we can unlock it now already */
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

    result=Curl_ftpsendf(conn, "PORT %d,%d,%d,%d,%d,%d",
                         ip[0], ip[1], ip[2], ip[3],
                         porttouse >> 8,
                         porttouse & 255);
    if(result)
      return result;

  }
  else
    return CURLE_FTP_PORT_FAILED;

  Curl_freeaddrinfo(addr);

  result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  if(result)
    return result;

  if(ftpcode != 200) {
    failf(data, "Server does not grok PORT, try without it!");
    return CURLE_FTP_PORT_FAILED;
  }
#endif /* end of ipv4-specific code */

  return CURLE_OK;
}

/***********************************************************************
 *
 * ftp_use_pasv()
 *
 * Send the PASV command. PASV is the ftp client's way of asking the server to
 * open a second port that we can connect to (for the data transfer). This is
 * the opposite of PORT.
 */

static
CURLcode ftp_use_pasv(struct connectdata *conn,
                      bool *connected)
{
  struct SessionHandle *data = conn->data;
  ssize_t nread;
  char *buf = data->state.buffer; /* this is our buffer */
  int ftpcode; /* receive FTP response codes in this */
  CURLcode result;
  struct Curl_dns_entry *addr=NULL;
  Curl_addrinfo *conninfo;
  int rc;

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
  int results[] = { 229, 227, 0 };
  int modeoff;
  unsigned short connectport; /* the local port connect() should use! */
  unsigned short newport=0; /* remote port, not necessary the local one */

  /* newhost must be able to hold a full IP-style address in ASCII, which
     in the IPv6 case means 5*8-1 = 39 letters */
#define NEWHOST_BUFSIZE 48
  char newhost[NEWHOST_BUFSIZE];

#ifdef PF_INET6
  if(!conn->bits.ftp_use_epsv &&
     (conn->ip_addr->ai_family == PF_INET6)) {
    /* EPSV is disabled but we are connected to a IPv6 host, so we ignore the
       request! */
    conn->bits.ftp_use_epsv = TRUE;
  }
#endif

  for (modeoff = (conn->bits.ftp_use_epsv?0:1);
       mode[modeoff]; modeoff++) {
    result = Curl_ftpsendf(conn, "%s", mode[modeoff]);
    if(result)
      return result;
    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;
    if (ftpcode == results[modeoff])
      break;

    if(modeoff == 0) {
      /* EPSV is not supported, disable it for next transfer */
      conn->bits.ftp_use_epsv = FALSE;
      infof(data, "disabling EPSV usage\n");
    }
  }

  if (!mode[modeoff]) {
    failf(data, "Odd return code after PASV");
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }
  else if (227 == results[modeoff]) {
    int ip[4];
    int port[2];
    char *str=buf;

    /*
     * New 227-parser June 3rd 1999.
     * It now scans for a sequence of six comma-separated numbers and
     * will take them as IP+port indicators.
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
      failf(data, "Couldn't interpret this 227-reply: %s", buf);
      return CURLE_FTP_WEIRD_227_FORMAT;
    }

    snprintf(newhost, sizeof(newhost),
             "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    newport = (port[0]<<8) + port[1];
  }
  else if (229 == results[modeoff]) {
    char *ptr = strchr(buf, '(');
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
        char sep1 = separator[0];
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

          /* We must use the same IP we are already connected to */
          Curl_printable_address(conn->ip_addr, newhost, NEWHOST_BUFSIZE);
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
  else
    return CURLE_FTP_CANT_RECONNECT;

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
      rc = Curl_wait_for_resolv(conn, &addr);

    connectport =
      (unsigned short)conn->port; /* we connect to the proxy's port */

  }
  else {
    /* normal, direct, ftp connection */
    rc = Curl_resolv(conn, newhost, newport, &addr);
    if(rc == CURLRESOLV_PENDING)
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
                            connected);

  Curl_resolv_unlock(data, addr); /* we're done using this address */

  if(result)
    return result;

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
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = Curl_ConnectHTTPProxyTunnel(conn, SECONDARYSOCKET,
                                         newhost, newport);
    if(CURLE_OK != result)
      return result;
  }
#endif   /* CURL_DISABLE_HTTP */

  return CURLE_OK;
}

/*
 * Curl_ftp_nextconnect()
 *
 * This function shall be called when the second FTP connection has been
 * established and is confirmed connected.
 */

CURLcode Curl_ftp_nextconnect(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  char *buf = data->state.buffer; /* this is our buffer */
  CURLcode result;
  ssize_t nread;
  int ftpcode; /* for ftp status */

  /* the ftp struct is already inited in Curl_ftp_connect() */
  struct FTP *ftp = conn->proto.ftp;
  curl_off_t *bytecountp = ftp->bytecountp;

  if(data->set.upload) {

    /* Set type to binary (unless specified ASCII) */
    result = ftp_transfertype(conn, data->set.ftp_ascii);
    if(result)
      return result;

    /* Send any PREQUOTE strings after transfer type is set? (Wesley Laxton)*/
    if(data->set.prequote) {
      if ((result = ftp_sendquote(conn, data->set.prequote)) != CURLE_OK)
        return result;
    }

    if(conn->resume_from) {
      /* we're about to continue the uploading of a file */
      /* 1. get already existing file's size. We use the SIZE
         command for this which may not exist in the server!
         The SIZE command is not in RFC959. */

      /* 2. This used to set REST. But since we can do append, we
         don't another ftp command. We just skip the source file
         offset and then we APPEND the rest on the file instead */

      /* 3. pass file-size number of bytes in the source file */
      /* 4. lower the infilesize counter */
      /* => transfer as usual */

      if(conn->resume_from < 0 ) {
        /* we could've got a specified offset from the command line,
           but now we know we didn't */
        curl_off_t gottensize;

        if(CURLE_OK != ftp_getsize(conn, ftp->file, &gottensize)) {
          failf(data, "Couldn't get remote file size");
          return CURLE_FTP_COULDNT_GET_SIZE;
        }
        conn->resume_from = gottensize;
      }

      if(conn->resume_from) {
        /* do we still game? */
        curl_off_t passed=0;
        /* enable append instead */
        data->set.ftp_append = 1;

        /* Now, let's read off the proper amount of bytes from the
           input. If we knew it was a proper file we could've just
           fseek()ed but we only have a stream here */
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
        }
        while(passed != conn->resume_from);

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

            return CURLE_OK;
          }
        }
        /* we've passed, proceed as normal */
      }
    }

    /* Send everything on data->state.in to the socket */
    if(data->set.ftp_append) {
      /* we append onto the file instead of rewriting it */
      FTPSENDF(conn, "APPE %s", ftp->file);
    }
    else {
      FTPSENDF(conn, "STOR %s", ftp->file);
    }

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;

    if(ftpcode>=400) {
      failf(data, "Failed FTP upload:%s", buf+3);
      /* oops, we never close the sockets! */
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

    if(data->set.ftp_use_port) {
      /* PORT means we are now awaiting the server to connect to us. */
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

    *bytecountp=0;

    /* When we know we're uploading a specified file, we can get the file
       size prior to the actual upload. */

    Curl_pgrsSetUploadSize(data, data->set.infilesize);

    result = Curl_Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                           SECONDARYSOCKET, bytecountp);
    if(result)
      return result;

  }
  else if(!conn->bits.no_body) {
    /* Retrieve file or directory */
    bool dirlist=FALSE;
    curl_off_t downloadsize=-1;

    if(conn->bits.use_range && conn->range) {
      curl_off_t from, to;
      curl_off_t totalsize=-1;
      char *ptr;
      char *ptr2;

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

    if((data->set.ftp_list_only) || !ftp->file) {
      /* The specified path ends with a slash, and therefore we think this
         is a directory that is requested, use LIST. But before that we
         need to set ASCII transfer mode. */
      dirlist = TRUE;

      /* Set type to ASCII */
      result = ftp_transfertype(conn, TRUE /* ASCII enforced */);
      if(result)
        return result;

      /* if this output is to be machine-parsed, the NLST command will be
         better used since the LIST command output is not specified or
         standard in any way */

      FTPSENDF(conn, "%s",
            data->set.customrequest?data->set.customrequest:
            (data->set.ftp_list_only?"NLST":"LIST"));
    }
    else {
      curl_off_t foundsize;

      /* Set type to binary (unless specified ASCII) */
      result = ftp_transfertype(conn, data->set.ftp_ascii);
      if(result)
        return result;

      /* Send any PREQUOTE strings after transfer type is set? */
      if(data->set.prequote) {
        if ((result = ftp_sendquote(conn, data->set.prequote)) != CURLE_OK)
          return result;
      }

      /* Attempt to get the size, it'll be useful in some cases: for resumed
         downloads and when talking to servers that don't give away the size
         in the RETR response line. */
      result = ftp_getsize(conn, ftp->file, &foundsize);
      if(CURLE_OK == result) {
        if (data->set.max_filesize && foundsize > data->set.max_filesize) {
          failf(data, "Maximum file size exceeded");
          return CURLE_FILESIZE_EXCEEDED;
        }
        downloadsize = foundsize;
      }

      if(conn->resume_from) {

        /* Daniel: (August 4, 1999)
         *
         * We start with trying to use the SIZE command to figure out the size
         * of the file we're gonna get. If we can get the size, this is by far
         * the best way to know if we're trying to resume beyond the EOF.
         *
         * Daniel, November 28, 2001. We *always* get the size on downloads
         * now, so it is done before this even when not doing resumes. I saved
         * the comment above for nostalgical reasons! ;-)
         */
        if(CURLE_OK != result) {
          infof(data, "ftp server doesn't support SIZE\n");
          /* We couldn't get the size and therefore we can't know if there
             really is a part of the file left to get, although the server
             will just close the connection when we start the connection so it
             won't cause us any harm, just not make us exit as nicely. */
        }
        else {
          /* We got a file size report, so we check that there actually is a
             part of the file left to get, or else we go home.  */
          if(conn->resume_from< 0) {
            /* We're supposed to download the last abs(from) bytes */
            if(foundsize < -conn->resume_from) {
              failf(data, "Offset (%" FORMAT_OFF_T
                    ") was beyond file size (%" FORMAT_OFF_T ")",
                    conn->resume_from, foundsize);
              return CURLE_BAD_DOWNLOAD_RESUME;
            }
            /* convert to size to download */
            downloadsize = -conn->resume_from;
            /* download from where? */
            conn->resume_from = foundsize - downloadsize;
          }
          else {
            if(foundsize < conn->resume_from) {
              failf(data, "Offset (%" FORMAT_OFF_T
                    ") was beyond file size (%" FORMAT_OFF_T ")",
                    conn->resume_from, foundsize);
              return CURLE_BAD_DOWNLOAD_RESUME;
            }
            /* Now store the number of bytes we are expected to download */
            downloadsize = foundsize-conn->resume_from;
          }
        }

        if (downloadsize == 0) {
          /* no data to transfer */
          result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
          infof(data, "File already completely downloaded\n");

          /* Set no_transfer so that we won't get any error in Curl_ftp_done()
           * because we didn't transfer the any file */
          ftp->no_transfer = TRUE;
          return CURLE_OK;
        }

        /* Set resume file transfer offset */
        infof(data, "Instructs server to resume from offset %" FORMAT_OFF_T
              "\n",
              conn->resume_from);

        FTPSENDF(conn, "REST %" FORMAT_OFF_T, conn->resume_from);

        result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
        if(result)
          return result;

        if(ftpcode != 350) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return CURLE_FTP_COULDNT_USE_REST;
        }
      }

      FTPSENDF(conn, "RETR %s", ftp->file);
    }

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if(result)
      return result;

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
       * It appears that there are FTP-servers that return size 0 for files
       * when SIZE is used on the file while being in BINARY mode. To work
       * around that (stupid) behavior, we attempt to parse the RETR response
       * even if the SIZE returned size zero.
       *
       * Debugging help from Salvatore Sorrentino on February 26, 2003.
       */

      if(!dirlist &&
         !data->set.ftp_ascii &&
         (downloadsize < 1)) {
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
            /* scan for the parenthesis and break there */
            if('(' == *bytes)
              break;
            /* if only skip digits, or else we're in deep trouble */
            if(!isdigit((int)*bytes)) {
              bytes=NULL;
              break;
            }
            /* one more estep backwards */
            bytes--;
          }
          /* only if we have nothing but digits: */
          if(bytes++) {
            /* get the number! */
            size = curlx_strtoofft(bytes, NULL, 0);
          }

        }
      }
      else if(downloadsize > -1)
        size = downloadsize;

      if(data->set.ftp_use_port) {
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

      infof(data, "Getting file with size: %" FORMAT_OFF_T "\n", size);

      /* FTP download: */
      result=Curl_Transfer(conn, SECONDARYSOCKET, size, FALSE,
                           bytecountp,
                           -1, NULL); /* no upload here */
      if(result)
        return result;
    }
    else {
      if(dirlist && (ftpcode == 450)) {
        /* simply no matching files */
        ftp->no_transfer = TRUE; /* don't think we should download anything */
      }
      else {
        failf(data, "%s", buf+4);
        return CURLE_FTP_COULDNT_RETR_FILE;
      }
    }

  }
  /* end of transfer */

  return CURLE_OK;
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
                     bool *connected)  /* for the TCP connect status after
                                          PASV / PORT */
{
  /* this is FTP and no proxy */
  CURLcode result=CURLE_OK;
  struct SessionHandle *data=conn->data;
  char *buf = data->state.buffer; /* this is our buffer */

  /* the ftp struct is already inited in Curl_ftp_connect() */
  struct FTP *ftp = conn->proto.ftp;

  /* Send any QUOTE strings? */
  if(data->set.quote) {
    if ((result = ftp_sendquote(conn, data->set.quote)) != CURLE_OK)
      return result;
  }

  result = ftp_cwd_and_create_path(conn);
  if (result)
    return result;

  /* Requested time of file or time-depended transfer? */
  if((data->set.get_filetime || data->set.timecondition) &&
     ftp->file) {
    result = ftp_getfiletime(conn, ftp->file);
    switch( result )
      {
      case CURLE_FTP_COULDNT_RETR_FILE:
      case CURLE_OK:
        if(data->set.timecondition) {
          if((data->info.filetime > 0) && (data->set.timevalue > 0)) {
            switch(data->set.timecondition) {
            case CURL_TIMECOND_IFMODSINCE:
            default:
              if(data->info.filetime < data->set.timevalue) {
                infof(data, "The requested document is not new enough\n");
                ftp->no_transfer = TRUE; /* mark this to not transfer data */
                return CURLE_OK;
              }
              break;
            case CURL_TIMECOND_IFUNMODSINCE:
              if(data->info.filetime > data->set.timevalue) {
                infof(data, "The requested document is not old enough\n");
                ftp->no_transfer = TRUE; /* mark this to not transfer data */
                return CURLE_OK;
              }
              break;
            } /* switch */
          }
          else {
            infof(data, "Skipping time comparison\n");
          }
        }
        break;
      default:
        return result;
      } /* switch */
  }

  /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which in FTP can't be much more than the file size and
     date. */
  if(conn->bits.no_body && data->set.include_header && ftp->file) {
    /* The SIZE command is _not_ RFC 959 specified, and therefor many servers
       may not support it! It is however the only way we have to get a file's
       size! */
    curl_off_t filesize;
    ssize_t nread;
    int ftpcode;

    ftp->no_transfer = TRUE; /* this means no actual transfer is made */

    /* Some servers return different sizes for different modes, and thus we
       must set the proper type before we check the size */
    result = ftp_transfertype(conn, data->set.ftp_ascii);
    if(result)
      return result;

    /* failing to get size is not a serious error */
    result = ftp_getsize(conn, ftp->file, &filesize);

    if(CURLE_OK == result) {
      snprintf(buf, sizeof(data->state.buffer),
               "Content-Length: %" FORMAT_OFF_T "\r\n", filesize);
      result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
      if(result)
        return result;
    }

    /* Determine if server can respond to REST command and therefore
       whether it can do a range */
    FTPSENDF(conn, "REST 0", NULL);
    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);

    if ((CURLE_OK == result) && (ftpcode == 350)) {
      result = Curl_client_write(data, CLIENTWRITE_BOTH,
                                 (char *)"Accept-ranges: bytes\r\n", 0);
      if(result)
        return result;
    }

    /* If we asked for a time of the file and we actually got one as
       well, we "emulate" a HTTP-style header in our output. */

#ifdef HAVE_STRFTIME
    if(data->set.get_filetime && (data->info.filetime>=0) ) {
      struct tm *tm;
      time_t clock = (time_t)data->info.filetime;
#ifdef HAVE_GMTIME_R
      struct tm buffer;
      tm = (struct tm *)gmtime_r(&clock, &buffer);
#else
      tm = gmtime(&clock);
#endif
      /* format: "Tue, 15 Nov 1994 12:45:26" */
      strftime(buf, BUFSIZE-1, "Last-Modified: %a, %d %b %Y %H:%M:%S GMT\r\n",
               tm);
      result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
      if(result)
        return result;
    }
#endif

    return CURLE_OK;
  }

  if(conn->bits.no_body)
    /* doesn't really transfer any data */
    ftp->no_transfer = TRUE;
  /* Get us a second connection up and connected */
  else if(data->set.ftp_use_port) {
    /* We have chosen to use the PORT command */
    result = ftp_use_port(conn);
    if(CURLE_OK == result) {
      /* we have the data connection ready */
      infof(data, "Ordered connect of the data stream with PORT!\n");
      *connected = TRUE; /* mark us "still connected" */
    }
  }
  else {
    /* We have chosen (this is default) to use the PASV command */
    result = ftp_use_pasv(conn, connected);
    if(CURLE_OK == result && *connected)
      infof(data, "Connected the data stream with PASV!\n");
  }

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
CURLcode Curl_ftp(struct connectdata *conn)
{
  CURLcode retcode = CURLE_OK;

  retcode = ftp_parse_url_path(conn);
  if (retcode)
    return retcode;

  if (conn->sec_conn) /* 3rd party transfer */
    retcode = ftp_3rdparty(conn);
  else
    retcode = ftp_regular_transfer(conn);

  return retcode;
}

/***********************************************************************
 *
 * Curl_ftpsendf()
 *
 * Sends the formated string as a ftp command to a ftp server
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 */
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
      Curl_debug(conn->data, CURLINFO_HEADER_OUT, sptr, bytes_written, conn->host.dispname);

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
  ssize_t nread;
  int ftpcode;
  CURLcode ret = CURLE_OK;

  if(conn->proto.ftp->ctl_valid) {
    ret = Curl_ftpsendf(conn, "%s", "QUIT");
    if(CURLE_OK == ret)
      ret = Curl_GetFTPResponse(&nread, conn, &ftpcode);
  }

  return ret;
}

/***********************************************************************
 *
 * Curl_ftp_disconnect()
 *
 * Disconnect from an FTP server. Cleanup protocol-specific per-connection
 * resources
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

  if (data->set.pasvHost == CURL_TARGET_PASV) {
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
  if (result) return result;
  if (ftpcode != 227) {
    failf(data, "Odd return code after PASV:%s", buf + 3);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

  while (*str) {
    if (6 == sscanf(str, "%d,%d,%d,%d,%d,%d",
                    &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]))
      break;
    str++;
  }

  if (!*str) {
    failf(pasv_conn->data, "Couldn't interpret this 227-reply: %s", buf);
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
    failf(data, "PORT command attempts failed:%s", buf + 3);
    return CURLE_FTP_PORT_FAILED;
  }

  /* we might append onto the file instead of overwriting it */
  stor_cmd = data->set.ftp_append?"APPE":"STOR";

  /* transfers file between remote hosts */
  FTPSENDF(sec_conn, "RETR %s", data->set.source_path);

  if(data->set.pasvHost == CURL_TARGET_PASV) {

    result = Curl_GetFTPResponse(&nread, sec_conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode != 150) {
      failf(data, "Failed RETR: %s", buf + 4);
      return CURLE_FTP_COULDNT_RETR_FILE;
    }

    result = Curl_ftpsendf(conn, "%s %s", stor_cmd, conn->path);
    if(CURLE_OK == result)
      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode != 150) {
      failf(data, "Failed FTP upload: %s", buf + 4);
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

  }
  else {

    result = Curl_ftpsendf(conn, "%s %s", stor_cmd, conn->path);
    if(CURLE_OK == result)
      result = Curl_GetFTPResponse(&nread, sec_conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode != 150) {
      failf(data, "Failed FTP upload: %s", buf + 4);
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
    if (result)
      return result;

    if (ftpcode != 150) {
      failf(data, "Failed FTP upload: %s", buf + 4);
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
  ftp->dirs = (char **)malloc(ftp->diralloc * sizeof(ftp->dirs[0]));
  if(!ftp->dirs)
    return CURLE_OUT_OF_MEMORY;
  ftp->dirs[0] = NULL; /* to start with */

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
  }
  else
    ftp->file=NULL; /* instead of point to a zero byte, we make it a NULL
                       pointer */

  ftp->cwddone = FALSE; /* default to not done */

  dlen = conn->path?strlen(conn->path):0;
  if(dlen && ftp->prevpath) {
    dlen -= ftp->file?strlen(ftp->file):0;
    if((dlen == strlen(ftp->prevpath)) &&
       curl_strnequal(conn->path, ftp->prevpath, dlen)) {
      infof(data, "Request has same path as previous transfer\n");
      ftp->cwddone = TRUE;
    }
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


/***********************************************************************
 *
 * ftp_regular_transfer()
 *
 * The input argument is already checked for validity.
 * Performs a regular transfer between local and remote hosts.
 *
 * ftp->ctl_valid starts out as FALSE, and gets set to TRUE if we reach the
 * Curl_ftp_done() function without finding any major problem.
 */
static
CURLcode ftp_regular_transfer(struct connectdata *conn)
{
  CURLcode retcode=CURLE_OK;
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

  retcode = ftp_perform(conn, &connected);

  if(CURLE_OK == retcode) {
    if(connected)
      retcode = Curl_ftp_nextconnect(conn);

    if(retcode && (conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD)) {
      /* Failure detected, close the second socket if it was created already */
      sclose(conn->sock[SECONDARYSOCKET]);
      conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
    }

    if(ftp->no_transfer)
      /* no data to transfer */
      retcode=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    else if(!connected)
      /* since we didn't connect now, we want do_more to get called */
      conn->bits.do_more = TRUE;
  }
  else
    freedirs(ftp);

  ftp->ctl_valid = TRUE; /* seems good */

  return retcode;
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
  CURLcode retcode = CURLE_OK;

  conn->proto.ftp->ctl_valid = conn->sec_conn->proto.ftp->ctl_valid = TRUE;
  conn->size = conn->sec_conn->size = -1;

  retcode = ftp_3rdparty_pretransfer(conn);
  if (!retcode)
    retcode = ftp_3rdparty_transfer(conn);

  return retcode;
}

#endif /* CURL_DISABLE_FTP */
