/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else /* some kind of unix */
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
#include <sys/utsname.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef	VMS
#include <inet.h>
#endif
#endif

#if defined(WIN32) && defined(__GNUC__) || defined(__MINGW32__)
#include <errno.h>
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

#ifdef KRB4
#include "security.h"
#include "krb4.h"
#endif

#include "strequal.h"
#include "ssluse.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* Local API functions */
static CURLcode _ftp_sendquote(struct connectdata *conn, struct curl_slist *quote);
static CURLcode _ftp_cwd(struct connectdata *conn, char *path);

/* easy-to-use macro: */
#define ftpsendf Curl_ftpsendf

static CURLcode AllowServerConnect(struct UrlData *data,
                                   struct connectdata *conn,
                                   int sock)
{
  fd_set rdset;
  struct timeval dt;
  
  FD_ZERO(&rdset);

  FD_SET(sock, &rdset);

  /* we give the server 10 seconds to connect to us */
  dt.tv_sec = 10;
  dt.tv_usec = 0;

  switch ( select(sock+1, &rdset, NULL, NULL, &dt)) {
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
      int s;
      size_t size = sizeof(struct sockaddr_in);
      struct sockaddr_in add;

      getsockname(sock, (struct sockaddr *) &add, (socklen_t *)&size);
      s=accept(sock, (struct sockaddr *) &add, (socklen_t *)&size);

      sclose(sock); /* close the first socket */

      if( -1 == s) {
	/* DIE! */
	failf(data, "Error accept()ing server connect");
	return CURLE_FTP_PORT_FAILED;
      }
      infof(data, "Connection accepted from server\n");

      conn->secondarysocket = s;
    }
    break;
  }
  return CURLE_OK;
}


/* --- parse FTP server responses --- */

#define lastline(line) (isdigit((int)line[0]) && isdigit((int)line[1]) && \
			isdigit((int)line[2]) && (' ' == line[3]))


int Curl_GetFTPResponse(int sockfd,
                        char *buf,
                        struct connectdata *conn,
                        int *ftpcode)
{
  /* Brand new implementation.
   * We cannot read just one byte per read() and then go back to select()
   * as it seems that the OpenSSL read() stuff doesn't grok that properly.
   *
   * Alas, read as much as possible, split up into lines, use the ending
   * line in a response or continue reading.
   */

  int nread;   /* total size read */
  int perline; /* count bytes per line */
  bool keepon=TRUE;
  ssize_t gotbytes;
  char *ptr;
  int timeout = 3600; /* default timeout in seconds */
  struct timeval interval;
  fd_set rkeepfd;
  fd_set readfd;
  struct UrlData *data = conn->data;
  char *line_start;
  int code=0; /* default "error code" to return */

#define SELECT_OK      0
#define SELECT_ERROR   1
#define SELECT_TIMEOUT 2
  int error = SELECT_OK;

  if(ftpcode)
    *ftpcode=0; /* 0 for errors */

  if(data->timeout) {
    /* if timeout is requested, find out how much remaining time we have */
    timeout = data->timeout - /* timeout time */
      (Curl_tvlong(Curl_tvnow()) - Curl_tvlong(conn->now)); /* spent time */
    if(timeout <=0 ) {
      failf(data, "Transfer aborted due to timeout");
      return -SELECT_TIMEOUT; /* already too little time */
    }
  }

  FD_ZERO (&readfd);		/* clear it */
  FD_SET (sockfd, &readfd);     /* read socket */

  /* get this in a backup variable to be able to restore it on each lap in the
     select() loop */
  rkeepfd = readfd;

  ptr=buf;
  line_start = buf;

  nread=0;
  perline=0;
  keepon=TRUE;

  while((nread<BUFSIZE) && (keepon && !error)) {
    readfd = rkeepfd;		   /* set every lap */
    interval.tv_sec = timeout;
    interval.tv_usec = 0;

    switch (select (sockfd+1, &readfd, NULL, NULL, &interval)) {
    case -1: /* select() error, stop reading */
      error = SELECT_ERROR;
      failf(data, "Transfer aborted due to select() error");
      break;
    case 0: /* timeout */
      error = SELECT_TIMEOUT;
      failf(data, "Transfer aborted due to timeout");
      break;
    default:
      /*
       * This code previously didn't use the kerberos sec_read() code
       * to read, but when we use Curl_read() it may do so. Do confirm
       * that this is still ok and then remove this comment!
       */
      if(CURLE_OK != Curl_read(conn, sockfd, ptr, BUFSIZE-nread, &gotbytes))
        keepon = FALSE;
      else if(gotbytes <= 0) {
        keepon = FALSE;
        error = SELECT_ERROR;
        failf(data, "Connection aborted");
      }
      else {
        /* we got a whole chunk of data, which can be anything from one
         * byte to a set of lines and possible just a piece of the last
         * line */
        int i;

        nread += gotbytes;
        for(i=0; i< gotbytes; ptr++, i++) {
          perline++;
          if(*ptr=='\n') {
            /* a newline is CRLF in ftp-talk, so the CR is ignored as
               the line isn't really terminated until the LF comes */

            /* output debug output if that is requested */
            if(data->bits.verbose) {
              fputs("< ", data->err);
              fwrite(line_start, perline, 1, data->err);
              /* no need to output LF here, it is part of the data */
            }

            if(perline>3 && lastline(line_start)) {
              /* This is the end of the last line, copy the last
               * line to the start of the buffer and zero terminate,
               * for old times sake (and krb4)! */
              char *moo;
              int i;
              for(moo=line_start, i=0; moo<ptr; moo++, i++)
                buf[i] = *moo;
              moo[i]=0; /* zero terminate */
              keepon=FALSE;
              break;
            }
            perline=0; /* line starts over here */
            line_start = ptr+1;
          }
        }
      }
      break;
    } /* switch */
  } /* while there's buffer left and loop is requested */

  if(!error)
    code = atoi(buf);

#if KRB4
  /* handle the security-oriented responses 6xx ***/
  /* FIXME: some errorchecking perhaps... ***/
  switch(code) {
  case 631:
    sec_read_msg(conn, buf, prot_safe);
    break;
  case 632:
    sec_read_msg(conn, buf, prot_private);
    break;
  case 633:
    sec_read_msg(conn, buf, prot_confidential);
    break;
  default:
    /* normal ftp stuff we pass through! */
    break;
  }
#endif

  if(error)
    return -error;

  if(ftpcode)
    *ftpcode=code; /* return the initial number like this */

  return nread; /* total amount of bytes read */
}

/* -- who are we? -- */
static char *getmyhost(char *buf, int buf_size)
{
#if defined(HAVE_GETHOSTNAME)
  gethostname(buf, buf_size);
#elif defined(HAVE_UNAME)
  struct utsname ugnm;
  strncpy(buf, uname(&ugnm) < 0 ? "localhost" : ugnm.nodename, buf_size - 1);
  buf[buf_size - 1] = '\0';
#else
  /* We have no means of finding the local host name! */
  strncpy(buf, "localhost", buf_size);
  buf[buf_size - 1] = '\0';
#endif
  return buf;
}

/* ftp_connect() should do everything that is to be considered a part
   of the connection phase. */
CURLcode Curl_ftp_connect(struct connectdata *conn)
{
  /* this is FTP and no proxy */
  int nread;
  struct UrlData *data=conn->data;
  char *buf = data->buffer; /* this is our buffer */
  struct FTP *ftp;
  CURLcode result;
  int ftpcode;

  myalarm(0); /* switch off the alarm stuff */

  ftp = (struct FTP *)malloc(sizeof(struct FTP));
  if(!ftp)
    return CURLE_OUT_OF_MEMORY;

  memset(ftp, 0, sizeof(struct FTP));
  conn->proto.ftp = ftp;

  /* We always support persistant connections on ftp */
  conn->bits.close = FALSE;

  /* get some initial data into the ftp struct */
  ftp->bytecountp = &conn->bytecount;

  /* duplicate to keep them even when the data struct changes */
  ftp->user = strdup(data->user);
  ftp->passwd = strdup(data->passwd);

  if (data->bits.tunnel_thru_httpproxy) {
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = Curl_ConnectHTTPProxyTunnel(conn, conn->firstsocket,
                                         conn->hostname, conn->remote_port);
    if(CURLE_OK != result)
      return result;
  }

  if(conn->protocol & PROT_FTPS) {
    /* FTPS is simply ftp with SSL for the control channel */
    /* now, perform the SSL initialization for this socket */
    result = Curl_SSLConnect(conn);
    if(result)
      return result;
  }


  /* The first thing we do is wait for the "220*" line: */
  nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
  if(nread < 0)
    return CURLE_OPERATION_TIMEOUTED;

  if(ftpcode != 220) {
    failf(data, "This doesn't seem like a nice ftp-server response");
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }

#ifdef KRB4
  /* if not anonymous login, try a secure login */
  if(data->bits.krb4) {

    /* request data protection level (default is 'clear') */
    sec_request_prot(conn, "private");

    /* We set private first as default, in case the line below fails to
       set a valid level */
    sec_request_prot(conn, data->krb4_level);

    if(sec_login(conn) != 0)
      infof(data, "Logging in with password in cleartext!\n");
    else
      infof(data, "Authentication successful\n");
  }
#endif
  
  /* send USER */
  ftpsendf(conn->firstsocket, conn, "USER %s", ftp->user);

  /* wait for feedback */
  nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
  if(nread < 0)
    return CURLE_OPERATION_TIMEOUTED;

  if(ftpcode == 530) {
    /* 530 User ... access denied
       (the server denies to log the specified user) */
    failf(data, "Access denied: %s", &buf[4]);
    return CURLE_FTP_ACCESS_DENIED;
  }
  else if(ftpcode == 331) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    ftpsendf(conn->firstsocket, conn, "PASS %s", ftp->passwd);
    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode == 530) {
      /* 530 Login incorrect.
         (the username and/or the password are incorrect) */
      failf(data, "the username and/or the password are incorrect");
      return CURLE_FTP_USER_PASSWORD_INCORRECT;
    }
    else if(ftpcode == 230) {
      /* 230 User ... logged in.
         (user successfully logged in) */
        
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
#ifdef KRB4
	/* we are logged in (with Kerberos)
	 * now set the requested protection level
	 */
    if(conn->sec_complete)
      sec_set_protection_level(conn);

    /* we may need to issue a KAUTH here to have access to the files
     * do it if user supplied a password
     */
    if(conn->data->passwd && *conn->data->passwd)
      krb_kauth(conn);
#endif
  }
  else {
    failf(data, "Odd return code after USER");
    return CURLE_FTP_WEIRD_USER_REPLY;
  }

  /* send PWD to discover our entry point */
  ftpsendf(conn->firstsocket, conn, "PWD");

  /* wait for feedback */
  nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
  if(nread < 0)
    return CURLE_OPERATION_TIMEOUTED;

  if(ftpcode == 257) {
    char *dir = (char *)malloc(nread+1);
    char *store=dir;
    char *ptr=&buf[4]; /* start on the first letter */
    
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
    }

  }
  else {
    /* We couldn't read the PWD response! */
  }

  return CURLE_OK;
}


/* argument is already checked for validity */
CURLcode Curl_ftp_done(struct connectdata *conn)
{
  struct UrlData *data = conn->data;
  struct FTP *ftp = conn->proto.ftp;
  ssize_t nread;
  char *buf = data->buffer; /* this is our buffer */
  struct curl_slist *qitem; /* QUOTE item */
  int ftpcode;

  if(data->bits.upload) {
    if((-1 != data->infilesize) && (data->infilesize != *ftp->bytecountp)) {
      failf(data, "Wrote only partial file (%d out of %d bytes)",
            *ftp->bytecountp, data->infilesize);
      return CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != conn->size) && (conn->size != *ftp->bytecountp) &&
       (conn->maxdownload != *ftp->bytecountp)) {
      failf(data, "Received only partial file");
      return CURLE_PARTIAL_FILE;
    }
    else if(!conn->bits.resume_done &&
            !data->bits.no_body &&
            (0 == *ftp->bytecountp)) {
      failf(data, "No data was received!");
      return CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

#ifdef KRB4
  sec_fflush_fd(conn, conn->secondarysocket);
#endif
  /* shut down the socket to inform the server we're done */
  sclose(conn->secondarysocket);
  conn->secondarysocket = -1;

  if(!data->bits.no_body && !conn->bits.resume_done) {  
    /* now let's see what the server says about the transfer we
       just performed: */
    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    /* 226 Transfer complete, 250 Requested file action okay, completed. */
    if((ftpcode != 226) && (ftpcode != 250)) {
      failf(data, "server did not report OK, got %d", ftpcode);
      return CURLE_FTP_WRITE_ERROR;
    }
  }

  conn->bits.resume_done = FALSE; /* clean this for next connection */

  /* Send any post-transfer QUOTE strings? */
  if(data->postquote) {
    CURLcode result = _ftp_sendquote(conn, data->postquote);
    return result;
  }

  return CURLE_OK;
}


static 
CURLcode _ftp_sendquote(struct connectdata *conn, struct curl_slist *quote)
{
  struct curl_slist *item;
  ssize_t            nread;
  int                ftpcode;

  item = quote;
  while (item) {
    if (item->data) {
      ftpsendf(conn->firstsocket, conn, "%s", item->data);

      nread = Curl_GetFTPResponse(conn->firstsocket, 
          conn->data->buffer, conn, &ftpcode);
      if (nread < 0)
        return CURLE_OPERATION_TIMEOUTED;

      if (ftpcode >= 400) {
        failf(conn->data, "QUOT string not accepted: %s", item->data);
        return CURLE_FTP_QUOTE_ERROR;
      }
    }

    ítem = item->next;
  }

  return CURLE_OK;
}

static 
CURLcode _ftp_cwd(struct connectdata *conn, char *path)
{
  ssize_t nread;
  int     ftpcode;
  
  ftpsendf(conn->firstsocket, conn, "CWD %s", path);
  nread = Curl_GetFTPResponse(conn->firstsocket, 
      conn->data->buffer, conn, &ftpcode);
  if (nread < 0)
    return CURLE_OPERATION_TIMEOUTED;

  if (ftpcode != 250) {
    failf(conn->data, "Couldn't change back to directory %s", path);
    return CURLE_FTP_ACCESS_DENIED;
  }
}

static
CURLcode _ftp(struct connectdata *conn)
{
  /* this is FTP and no proxy */
  ssize_t nread;
  CURLcode result;
  struct UrlData *data=conn->data;
  char *buf = data->buffer; /* this is our buffer */
  /* for the ftp PORT mode */
  int portsock=-1;
#if defined (HAVE_INET_NTOA_R)
  char ntoa_buf[64];
#endif
#ifdef ENABLE_IPV6
  struct addrinfo *ai;
#else
  struct sockaddr_in serv_addr;
  char hostent_buf[8192];
#endif

  struct curl_slist *qitem; /* QUOTE item */
  /* the ftp struct is already inited in ftp_connect() */
  struct FTP *ftp = conn->proto.ftp;

  long *bytecountp = ftp->bytecountp;
  int ftpcode; /* for ftp status */

  /* Send any QUOTE strings? */
  if(data->quote) {
    if ((result = _ftp_sendquote(conn, data->quote)) != CURLE_OK)
      return result;
  }
    
    /* This is a re-used connection. Since we change directory to where the
       transfer is taking place, we must now get back to the original dir
       where we ended up after login: */
  if (conn->bits.reuse) {
    if ((result = _ftp_cwd(conn, ftp->entrypath)) != CURLE_OK)
      return result;
  }


  /* change directory first! */
  if(ftp->dir && ftp->dir[0]) {
    ftpsendf(conn->firstsocket, conn, "CWD %s", ftp->dir);
    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode != 250) {
      failf(data, "Couldn't change to directory %s", ftp->dir);
      return CURLE_FTP_ACCESS_DENIED;
    }
  }

  if(data->bits.get_filetime && ftp->file) {
    /* we have requested to get the modified-time of the file, this is yet
       again a grey area as the MDTM is not kosher RFC959 */
    ftpsendf(conn->firstsocket, conn, "MDTM %s", ftp->file);

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode == 213) {
      /* we got a time. Format should be: "YYYYMMDDHHMMSS[.sss]" where the
         last .sss part is optional and means fractions of a second */
      int year, month, day, hour, minute, second;
      if(6 == sscanf(buf+4, "%04d%02d%02d%02d%02d%02d",
                     &year, &month, &day, &hour, &minute, &second)) {
        /* we have a time, reformat it */
        time_t secs=time(NULL);
        sprintf(buf, "%04d%02d%02d %02d:%02d:%02d",
                year, month, day, hour, minute, second);
        /* now, convert this into a time() value: */
        data->progress.filetime = curl_getdate(buf, &secs);
      }
      else {
        infof(data, "unsupported MDTM reply format\n");
      }
    }

  }

  /* If we have selected NOBODY, it means that we only want file information.
     Which in FTP can't be much more than the file size! */
  if(data->bits.no_body) {
    /* The SIZE command is _not_ RFC 959 specified, and therefor many servers
       may not support it! It is however the only way we have to get a file's
       size! */
    int filesize;

    /* Some servers return different sizes for different modes, and thus we
       must set the proper type before we check the size */
    ftpsendf(conn->firstsocket, conn, "TYPE %s",
             (data->bits.ftp_ascii)?"A":"I");

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode != 200) {
      failf(data, "Couldn't set %s mode",
            (data->bits.ftp_ascii)?"ASCII":"binary");
      return (data->bits.ftp_ascii)? CURLE_FTP_COULDNT_SET_ASCII:
        CURLE_FTP_COULDNT_SET_BINARY;
    }

    ftpsendf(conn->firstsocket, conn, "SIZE %s", ftp->file);

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode == 213) {

      /* get the size from the ascii string: */
      filesize = atoi(buf+4);

      sprintf(buf, "Content-Length: %d\r\n", filesize);
      result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
      if(result)
        return result;

#ifdef HAVE_STRFTIME
      if(data->bits.get_filetime && data->progress.filetime) {
        struct tm *tm;
#ifdef HAVE_LOCALTIME_R
        struct tm buffer;
        tm = (struct tm *)localtime_r(&data->progress.filetime, &buffer);
#else
        tm = localtime(&data->progress.filetime);
#endif
        /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
        strftime(buf, BUFSIZE-1, "Last-Modified: %a, %d %b %Y %H:%M:%S %Z\r\n",
                 tm);
        result = Curl_client_write(data, CLIENTWRITE_BOTH, buf, 0);
        if(result)
          return result;
      }
#endif
    }

    return CURLE_OK;
  }

  /* We have chosen to use the PORT command */
  if(data->bits.ftp_use_port) {
#ifdef ENABLE_IPV6
    struct addrinfo hints, *res, *ai;
    struct sockaddr_storage ss;
    socklen_t sslen;
    char hbuf[NI_MAXHOST];

    struct sockaddr *sa=(struct sockaddr *)&ss;
#ifdef NI_WITHSCOPEID
    const int niflags = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
#else
    const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#endif
    unsigned char *ap;
    unsigned char *pp;
    int alen, plen;
    char portmsgbuf[4096], tmp[4096];

    char *mode[] = { "EPRT", "LPRT", "PORT", NULL };
    char **modep;

    /*
     * we should use Curl_if2ip?  given pickiness of recent ftpd,
     * I believe we should use the same address as the control connection.
     */
    sslen = sizeof(ss);
    if (getsockname(conn->firstsocket, (struct sockaddr *)&ss, &sslen) < 0)
      return CURLE_FTP_PORT_FAILED;

    if (getnameinfo((struct sockaddr *)&ss, sslen, hbuf, sizeof(hbuf), NULL, 0,
	niflags))
      return CURLE_FTP_PORT_FAILED;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = sa->sa_family;
    /*hints.ai_family = ss.ss_family;
      this way can be used if sockaddr_storage is properly defined, as glibc 
      2.1.X doesn't do*/
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(hbuf, "0", &hints, &res))
      return CURLE_FTP_PORT_FAILED;

    portsock = -1;
    for (ai = res; ai; ai = ai->ai_next) {
      portsock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (portsock < 0)
	continue;

      if (bind(portsock, ai->ai_addr, ai->ai_addrlen) < 0) {
	sclose(portsock);
	portsock = -1;
	continue;
      }

      if (listen(portsock, 1) < 0) {
	sclose(portsock);
	portsock = -1;
	continue;
      }

      break;
    }
    if (portsock < 0) {
      failf(data, strerror(errno));
      freeaddrinfo(res);
      return CURLE_FTP_PORT_FAILED;
    }

    sslen = sizeof(ss);
    if (getsockname(portsock, sa, &sslen) < 0) {
      failf(data, strerror(errno));
      freeaddrinfo(res);
      return CURLE_FTP_PORT_FAILED;
    }

    for (modep = mode; modep && *modep; modep++) {
      int lprtaf, eprtaf;

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

      if (strcmp(*modep, "EPRT") == 0) {
	if (eprtaf < 0)
	  continue;
	if (getnameinfo((struct sockaddr *)&ss, sslen,
	    portmsgbuf, sizeof(portmsgbuf), tmp, sizeof(tmp), niflags))
	  continue;
	/* do not transmit IPv6 scope identifier to the wire */
	if (sa->sa_family == AF_INET6) {
	  char *q = strchr(portmsgbuf, '%');
	  if (q)
	    *q = '\0';
	}
	ftpsendf(conn->firstsocket, conn, "%s |%d|%s|%s|", *modep, eprtaf,
	    portmsgbuf, tmp);
      } else if (strcmp(*modep, "LPRT") == 0 ||
                 strcmp(*modep, "PORT") == 0) {
	int i;

        if (strcmp(*modep, "LPRT") == 0 && lprtaf < 0)
	  continue;
        if (strcmp(*modep, "PORT") == 0 && sa->sa_family != AF_INET)
	  continue;

	portmsgbuf[0] = '\0';
        if (strcmp(*modep, "LPRT") == 0) {
	  snprintf(tmp, sizeof(tmp), "%d,%d", lprtaf, alen);
	  if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >= sizeof(portmsgbuf)) {
	    continue;
	  }
	}
	for (i = 0; i < alen; i++) {
	  if (portmsgbuf[0])
	    snprintf(tmp, sizeof(tmp), ",%u", ap[i]);
	  else
	    snprintf(tmp, sizeof(tmp), "%u", ap[i]);
	  if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >= sizeof(portmsgbuf)) {
	    continue;
	  }
	}
        if (strcmp(*modep, "LPRT") == 0) {
	  snprintf(tmp, sizeof(tmp), ",%d", plen);
	  if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >= sizeof(portmsgbuf))
	    continue;
	}
	for (i = 0; i < plen; i++) {
	  snprintf(tmp, sizeof(tmp), ",%u", pp[i]);
	  if (strlcat(portmsgbuf, tmp, sizeof(portmsgbuf)) >= sizeof(portmsgbuf)) {
            continue;
	  }
	}
	ftpsendf(conn->firstsocket, conn, "%s %s", *modep, portmsgbuf);
      }

      nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
      if(nread < 0)
	return CURLE_OPERATION_TIMEOUTED;

      if (ftpcode != 200) {
	failf(data, "Server does not grok %s", *modep);
	continue;
      } else
	      break;
again:;
    }

    if (!*modep) {
      sclose(portsock);
      freeaddrinfo(res);
      return CURLE_FTP_PORT_FAILED;
    }

#else
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    char *hostdataptr=NULL;
    size_t size;
    unsigned short porttouse;
    char myhost[256] = "";

    if(data->ftpport) {
      if(Curl_if2ip(data->ftpport, myhost, sizeof(myhost))) {
        h = Curl_gethost(data, myhost, &hostdataptr);
      }
      else {
        if(strlen(data->ftpport)>1)
          h = Curl_gethost(data, data->ftpport, &hostdataptr);
        if(h)
          strcpy(myhost, data->ftpport); /* buffer overflow risk */
      }
    }
    if(! *myhost) {
      h=Curl_gethost(data,
                     getmyhost(myhost, sizeof(myhost)),
                     &hostdataptr);
    }
    infof(data, "We connect from %s\n", myhost);

    if ( h ) {
      if( (portsock = socket(AF_INET, SOCK_STREAM, 0)) >= 0 ) {

        /* we set the secondary socket variable to this for now, it
           is only so that the cleanup function will close it in case
           we fail before the true secondary stuff is made */
        conn->secondarysocket = portsock;

        memset((char *)&sa, 0, sizeof(sa));
        memcpy((char *)&sa.sin_addr,
               h->h_addr,
               h->h_length);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = 0;
        size = sizeof(sa);

        if(bind(portsock, (struct sockaddr *)&sa, size) >= 0) {
          /* we succeeded to bind */
          struct sockaddr_in add;
          size = sizeof(add);

          if(getsockname(portsock, (struct sockaddr *) &add,
                         (socklen_t *)&size)<0) {
            failf(data, "getsockname() failed");
            return CURLE_FTP_PORT_FAILED;
          }
          porttouse = ntohs(add.sin_port);

          if ( listen(portsock, 1) < 0 ) {
            failf(data, "listen(2) failed on socket");
            free(hostdataptr);
            return CURLE_FTP_PORT_FAILED;
          }
        }
        else {
          failf(data, "bind(2) failed on socket");
          free(hostdataptr);
          return CURLE_FTP_PORT_FAILED;
        }
      }
      else {
        failf(data, "socket(2) failed (%s)");
        free(hostdataptr);
        return CURLE_FTP_PORT_FAILED;
      }
      if(hostdataptr)
        /* free the memory used for name lookup */
        free(hostdataptr);
    }
    else {
      failf(data, "could't find my own IP address (%s)", myhost);
      return CURLE_FTP_PORT_FAILED;
    }
    {
      struct in_addr in;
      unsigned short ip[5];
      (void) memcpy(&in.s_addr, *h->h_addr_list, sizeof (in.s_addr));
#if defined (HAVE_INET_NTOA_R)
      /* ignore the return code from inet_ntoa_r() as it is int or
         char * depending on system */
      inet_ntoa_r(in, ntoa_buf, sizeof(ntoa_buf));
      sscanf( ntoa_buf, "%hu.%hu.%hu.%hu",
              &ip[0], &ip[1], &ip[2], &ip[3]);
#else
      sscanf( inet_ntoa(in), "%hu.%hu.%hu.%hu",
              &ip[0], &ip[1], &ip[2], &ip[3]);
#endif
      ftpsendf(conn->firstsocket, conn, "PORT %d,%d,%d,%d,%d,%d",
            ip[0], ip[1], ip[2], ip[3],
            porttouse >> 8,
            porttouse & 255);
    }

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode != 200) {
      failf(data, "Server does not grok PORT, try without it!");
      return CURLE_FTP_PORT_FAILED;
    }     
#endif /* ENABLE_IPV6 */
  }
  else { /* we use the PASV command */
#if 0
    /* no support for IPv6 passive mode yet */
    char *mode[] = { "EPSV", "LPSV", "PASV", NULL };
    int results[] = { 229, 228, 227, 0 };
#else
    const char *mode[] = { "PASV", NULL };
    int results[] = { 227, 0 };
#endif
    int modeoff;

    for (modeoff = 0; mode[modeoff]; modeoff++) {
      ftpsendf(conn->firstsocket, conn, mode[modeoff]);
      nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
      if(nread < 0)
	return CURLE_OPERATION_TIMEOUTED;

      if (ftpcode == results[modeoff])
	break;
    }

    if (!mode[modeoff]) {
      failf(data, "Odd return code after PASV");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
    else if (strcmp(mode[modeoff], "PASV") == 0) {
      int ip[4];
      int port[2];
      unsigned short newport; /* remote port, not necessary the local one */
      unsigned short connectport; /* the local port connect() should use! */
      char newhost[32];
#ifdef ENABLE_IPV6
      struct addrinfo *res;
#else
      struct hostent *he;
      char *hostdataptr=NULL;
      char *ip_addr;
#endif
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

      sprintf(newhost, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
      newport = (port[0]<<8) + port[1];
      if(data->bits.httpproxy) {
        /*
         * This is a tunnel through a http proxy and we need to connect to the
         * proxy again here. We already have the name info for it since the
         * previous lookup.
         */
#ifdef ENABLE_IPV6
        res = conn->hp;
#else
        he = conn->hp;
#endif
        connectport =
          (unsigned short)conn->port; /* we connect to the proxy's port */
      }
      else {
        /* normal, direct, ftp connection */
#ifdef ENABLE_IPV6
        res = Curl_getaddrinfo(data, newhost, newport);
        if(!res)
#else
        he = Curl_gethost(data, newhost, &hostdataptr);
        if(!he)
#endif
        {
          failf(data, "Can't resolve new host %s", newhost);
          return CURLE_FTP_CANT_GET_HOST;
        }
        connectport = newport; /* we connect to the remote port */
      }
	
#ifdef ENABLE_IPV6
      conn->secondarysocket = -1;
      for (ai = res; ai; ai = ai->ai_next) {
	/* XXX for now, we can do IPv4 only */
	if (ai->ai_family != AF_INET)
	  continue;

	conn->secondarysocket = socket(ai->ai_family, ai->ai_socktype,
	    ai->ai_protocol);
	if (conn->secondarysocket < 0)
	  continue;

	if(data->bits.verbose) {
	  char hbuf[NI_MAXHOST];
	  char nbuf[NI_MAXHOST];
	  char sbuf[NI_MAXSERV];
#ifdef NI_WITHSCOPEID
	  const int niflags = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
#else
	  const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#endif
	  if (getnameinfo(res->ai_addr, res->ai_addrlen, nbuf, sizeof(nbuf),
	      sbuf, sizeof(sbuf), niflags)) {
	    snprintf(nbuf, sizeof(nbuf), "?");
	    snprintf(sbuf, sizeof(sbuf), "?");
	  }
	  if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
	      NULL, 0, 0)) {
	    infof(data, "Connecting to %s port %s\n", nbuf, sbuf);
	  } else {
	    infof(data, "Connecting to %s (%s) port %s\n", hbuf, nbuf, sbuf);
	  }
	}

	if (connect(conn->secondarysocket, ai->ai_addr, ai->ai_addrlen) < 0) {
	  close(conn->secondarysocket);
	  conn->secondarysocket = -1;
	  continue;
	}

	break;
      }

      if (conn->secondarysocket < 0) {
	failf(data, strerror(errno));
        return CURLE_FTP_CANT_RECONNECT;
      }
#else
      conn->secondarysocket = socket(AF_INET, SOCK_STREAM, 0);

      memset((char *) &serv_addr, '\0', sizeof(serv_addr));
      memcpy((char *)&(serv_addr.sin_addr), he->h_addr, he->h_length);
      serv_addr.sin_family = he->h_addrtype;

      serv_addr.sin_port = htons(connectport);

      if(data->bits.verbose) {
        struct in_addr in;
        struct hostent * answer;

#if defined(HAVE_INET_ADDR)
        unsigned long address;
# if defined(HAVE_GETHOSTBYADDR_R)
        int h_errnop;
# endif

        address = inet_addr(newhost);
# ifdef HAVE_GETHOSTBYADDR_R

#  ifdef HAVE_GETHOSTBYADDR_R_5
        /* AIX, Digital Unix style:
           extern int gethostbyaddr_r(char *addr, size_t len, int type,
           struct hostent *htent, struct hostent_data *ht_data); */

        /* Fred Noz helped me try this out, now it at least compiles! */

        if(gethostbyaddr_r((char *) &address,
                           sizeof(address), AF_INET,
                           (struct hostent *)hostent_buf,
                           hostent_buf + sizeof(*answer)))
           answer=NULL;
                           
#  endif
#  ifdef HAVE_GETHOSTBYADDR_R_7
        /* Solaris and IRIX */
        answer = gethostbyaddr_r((char *) &address, sizeof(address), AF_INET,
                                 (struct hostent *)hostent_buf,
                                 hostent_buf + sizeof(*answer),
                                 sizeof(hostent_buf) - sizeof(*answer),
                                 &h_errnop);
#  endif
#  ifdef HAVE_GETHOSTBYADDR_R_8
        /* Linux style */
        if(gethostbyaddr_r((char *) &address, sizeof(address), AF_INET,
                           (struct hostent *)hostent_buf,
                           hostent_buf + sizeof(*answer),
                           sizeof(hostent_buf) - sizeof(*answer),
                           &answer,
                           &h_errnop))
           answer=NULL; /* error */
#  endif
        
# else
        answer = gethostbyaddr((char *) &address, sizeof(address), AF_INET);
# endif
#else
        answer = NULL;
#endif
        (void) memcpy(&in.s_addr, *he->h_addr_list, sizeof (in.s_addr));
        infof(data, "Connecting to %s (%s) port %u\n",
              answer?answer->h_name:newhost,
#if defined(HAVE_INET_NTOA_R)
              inet_ntoa_r(in, ip_addr=ntoa_buf, sizeof(ntoa_buf)),
#else
              ip_addr = inet_ntoa(in),
#endif
              connectport);
      }
	
      if(hostdataptr)
        free(hostdataptr);

      if (connect(conn->secondarysocket, (struct sockaddr *) &serv_addr,
                  sizeof(serv_addr)) < 0) {
        switch(errno) {
#ifdef ECONNREFUSED
          /* this should be made nicer */
        case ECONNREFUSED:
          failf(data, "Connection refused by ftp server");
          break;
#endif
#ifdef EINTR
        case EINTR:
          failf(data, "Connection timed out to ftp server");
          break;
#endif
        default:
          failf(data, "Can't connect to ftp server");
          break;
        }
        return CURLE_FTP_CANT_RECONNECT;
      }
#endif /*ENABLE_IPV6*/

      if (data->bits.tunnel_thru_httpproxy) {
        /* We want "seamless" FTP operations through HTTP proxy tunnel */
        result = Curl_ConnectHTTPProxyTunnel(conn, conn->secondarysocket,
                                             newhost, newport);
        if(CURLE_OK != result)
          return result;
      }
    } else {
      return CURLE_FTP_CANT_RECONNECT;
    }
  }
  /* we have the (new) data connection ready */
  infof(data, "Connected the data stream!\n");

  if(data->bits.upload) {

    /* Set type to binary (unless specified ASCII) */
    ftpsendf(conn->firstsocket, conn, "TYPE %s",
          (data->bits.ftp_ascii)?"A":"I");

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode != 200) {
      failf(data, "Couldn't set %s mode",
            (data->bits.ftp_ascii)?"ASCII":"binary");
      return (data->bits.ftp_ascii)? CURLE_FTP_COULDNT_SET_ASCII:
        CURLE_FTP_COULDNT_SET_BINARY;
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

        ftpsendf(conn->firstsocket, conn, "SIZE %s", ftp->file);

        nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(ftpcode != 213) {
          failf(data, "Couldn't get file size: %s", buf+4);
          return CURLE_FTP_COULDNT_GET_SIZE;
        }

        /* get the size from the ascii string: */
        conn->resume_from = atoi(buf+4);
      }

      if(conn->resume_from) {
        /* do we still game? */
        int passed=0;
        /* enable append instead */
        data->bits.ftp_append = 1;

        /* Now, let's read off the proper amount of bytes from the
           input. If we knew it was a proper file we could've just
           fseek()ed but we only have a stream here */
        do {
          int readthisamountnow = (conn->resume_from - passed);
          int actuallyread;

          if(readthisamountnow > BUFSIZE)
            readthisamountnow = BUFSIZE;

          actuallyread =
            data->fread(data->buffer, 1, readthisamountnow, data->in);

          passed += actuallyread;
          if(actuallyread != readthisamountnow) {
            failf(data, "Could only read %d bytes from the input\n",
                  passed);
            return CURLE_FTP_COULDNT_USE_REST;
          }
        }
        while(passed != conn->resume_from);

        /* now, decrease the size of the read */
        if(data->infilesize>0) {
          data->infilesize -= conn->resume_from;

          if(data->infilesize <= 0) {
            infof(data, "File already completely uploaded\n");

            /* no data to transfer */
            result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
            
            /* Set resume done so that we won't get any error in
             * Curl_ftp_done() because we didn't transfer the amount of bytes
             * that the local file file obviously is */
            conn->bits.resume_done = TRUE; 

            return CURLE_OK;
          }
        }
        /* we've passed, proceed as normal */
      }
    }

    /* Send everything on data->in to the socket */
    if(data->bits.ftp_append)
      /* we append onto the file instead of rewriting it */
      ftpsendf(conn->firstsocket, conn, "APPE %s", ftp->file);
    else
      ftpsendf(conn->firstsocket, conn, "STOR %s", ftp->file);

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(ftpcode>=400) {
      failf(data, "Failed FTP upload:%s", buf+3);
      /* oops, we never close the sockets! */
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

    if(data->bits.ftp_use_port) {
      result = AllowServerConnect(data, conn, portsock);
      if( result )
        return result;
    }

    *bytecountp=0;

    /* When we know we're uploading a specified file, we can get the file
       size prior to the actual upload. */

    Curl_pgrsSetUploadSize(data, data->infilesize);

    result = Curl_Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                      conn->secondarysocket, bytecountp);
    if(result)
      return result;
      
  }
  else {
    /* Retrieve file or directory */
    bool dirlist=FALSE;
    long downloadsize=-1;

    if(conn->bits.use_range && conn->range) {
      long from, to;
      int totalsize=-1;
      char *ptr;
      char *ptr2;

      from=strtol(conn->range, &ptr, 0);
      while(ptr && *ptr && (isspace((int)*ptr) || (*ptr=='-')))
        ptr++;
      to=strtol(ptr, &ptr2, 0);
      if(ptr == ptr2) {
        /* we didn't get any digit */
        to=-1;
      }
      if((-1 == to) && (from>=0)) {
        /* X - */
        conn->resume_from = from;
        infof(data, "FTP RANGE %d to end of file\n", from);
      }
      else if(from < 0) {
        /* -Y */
        totalsize = -from;
        conn->maxdownload = -from;
        conn->resume_from = from;
        infof(data, "FTP RANGE the last %d bytes\n", totalsize);
      }
      else {
        /* X-Y */
        totalsize = to-from;
        conn->maxdownload = totalsize+1; /* include the last mentioned byte */
        conn->resume_from = from;
        infof(data, "FTP RANGE from %d getting %d bytes\n", from,
              conn->maxdownload);
      }
      infof(data, "range-download from %d to %d, totally %d bytes\n",
            from, to, totalsize);
    }

    if((data->bits.ftp_list_only) || !ftp->file) {
      /* The specified path ends with a slash, and therefore we think this
         is a directory that is requested, use LIST. But before that we
         need to set ASCII transfer mode. */
      dirlist = TRUE;

      /* Set type to ASCII */
      ftpsendf(conn->firstsocket, conn, "TYPE A");
	
      nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
      if(nread < 0)
        return CURLE_OPERATION_TIMEOUTED;
	
      if(ftpcode != 200) {
        failf(data, "Couldn't set ascii mode");
        return CURLE_FTP_COULDNT_SET_ASCII;
      }

      /* if this output is to be machine-parsed, the NLST command will be
         better used since the LIST command output is not specified or
         standard in any way */

      ftpsendf(conn->firstsocket, conn, "%s",
            data->customrequest?data->customrequest:
            (data->bits.ftp_list_only?"NLST":"LIST"));
    }
    else {
      /* Set type to binary (unless specified ASCII) */
      ftpsendf(conn->firstsocket, conn, "TYPE %s",
               (data->bits.ftp_ascii)?"A":"I");

      nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
      if(nread < 0)
        return CURLE_OPERATION_TIMEOUTED;

      if(ftpcode != 200) {
        failf(data, "Couldn't set %s mode",
              (data->bits.ftp_ascii)?"ASCII":"binary");
        return (data->bits.ftp_ascii)? CURLE_FTP_COULDNT_SET_ASCII:
          CURLE_FTP_COULDNT_SET_BINARY;
      }

      if(conn->resume_from) {

        /* Daniel: (August 4, 1999)
         *
         * We start with trying to use the SIZE command to figure out the size
         * of the file we're gonna get. If we can get the size, this is by far
         * the best way to know if we're trying to resume beyond the EOF.  */

        ftpsendf(conn->firstsocket, conn, "SIZE %s", ftp->file);

        nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(ftpcode != 213) {
          infof(data, "server doesn't support SIZE: %s", buf+4);
          /* We couldn't get the size and therefore we can't know if there
             really is a part of the file left to get, although the server
             will just close the connection when we start the connection so it
             won't cause us any harm, just not make us exit as nicely. */
        }
        else {
          int foundsize=atoi(buf+4);
          /* We got a file size report, so we check that there actually is a
             part of the file left to get, or else we go home.  */
          if(conn->resume_from< 0) {
            /* We're supposed to download the last abs(from) bytes */
            if(foundsize < -conn->resume_from) {
              failf(data, "Offset (%d) was beyond file size (%d)",
                    conn->resume_from, foundsize);
              return CURLE_FTP_BAD_DOWNLOAD_RESUME;
            }
            /* convert to size to download */
            downloadsize = -conn->resume_from;
            /* download from where? */
            conn->resume_from = foundsize - downloadsize;
          }
          else {
            if(foundsize < conn->resume_from) {
              failf(data, "Offset (%d) was beyond file size (%d)",
                    conn->resume_from, foundsize);
              return CURLE_FTP_BAD_DOWNLOAD_RESUME;
            }
            /* Now store the number of bytes we are expected to download */
            downloadsize = foundsize-conn->resume_from;
          }
        }

	if (downloadsize == 0) {
          /* no data to transfer */
          result=Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
	  infof(data, "File already completely downloaded\n");

          /* Set resume done so that we won't get any error in Curl_ftp_done()
           * because we didn't transfer the amount of bytes that the remote
           * file obviously is */
          conn->bits.resume_done = TRUE; 

	  return CURLE_OK;
	}
	
        /* Set resume file transfer offset */
        infof(data, "Instructs server to resume from offset %d\n",
              conn->resume_from);

        ftpsendf(conn->firstsocket, conn, "REST %d", conn->resume_from);

        nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(ftpcode != 350) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return CURLE_FTP_COULDNT_USE_REST;
        }
      }

      ftpsendf(conn->firstsocket, conn, "RETR %s", ftp->file);
    }

    nread = Curl_GetFTPResponse(conn->firstsocket, buf, conn, &ftpcode);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

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

      int size=-1; /* default unknown size */

      if(!dirlist &&
         !data->bits.ftp_ascii &&
         (-1 == downloadsize)) {
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
          int index=bytes-buf;
          /* this is a hint there is size information in there! ;-) */
          while(--index) {
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
            size = atoi(bytes);
          }
            
        }
      }
      else if(downloadsize > -1)
        size = downloadsize;

      if(data->bits.ftp_use_port) {
        result = AllowServerConnect(data, conn, portsock);
        if( result )
          return result;
      }

      infof(data, "Getting file with size: %d\n", size);

      /* FTP download: */
      result=Curl_Transfer(conn, conn->secondarysocket, size, FALSE,
                      bytecountp,
                      -1, NULL); /* no upload here */
      if(result)
        return result;
    }
    else {
      failf(data, "%s", buf+4);
      return CURLE_FTP_COULDNT_RETR_FILE;
    }
	
  }
  /* end of transfer */

  return CURLE_OK;
}

/* -- deal with the ftp server!  -- */

/* argument is already checked for validity */
CURLcode Curl_ftp(struct connectdata *conn)
{
  CURLcode retcode;

  struct UrlData *data = conn->data;
  struct FTP *ftp;
  int dirlength=0; /* 0 forces strlen() */

  /* the ftp struct is already inited in ftp_connect() */
  ftp = conn->proto.ftp;

  /* We split the path into dir and file parts *before* we URLdecode
     it */
  ftp->file = strrchr(conn->ppath, '/');
  if(ftp->file) {
    if(ftp->file != conn->ppath)
      dirlength=ftp->file-conn->ppath; /* don't count the traling slash */

    ftp->file++; /* point to the first letter in the file name part or
                    remain NULL */
  }
  else {
    ftp->file = conn->ppath; /* there's only a file part */
  }

  if(*ftp->file) {
    ftp->file = curl_unescape(ftp->file, 0);
    if(NULL == ftp->file) {
      failf(data, "no memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else
    ftp->file=NULL; /* instead of point to a zero byte, we make it a NULL
                       pointer */

  ftp->urlpath = conn->ppath;
  if(dirlength) {
    ftp->dir = curl_unescape(ftp->urlpath, dirlength);
    if(NULL == ftp->dir) {
      if(ftp->file)
        free(ftp->file);
      failf(data, "no memory");
      return CURLE_OUT_OF_MEMORY; /* failure */
    }
  }
  else
    ftp->dir = NULL;

  retcode = _ftp(conn);

  /* clean up here, success or error doesn't matter */
  if(ftp->file)
    free(ftp->file);
  if(ftp->dir)
    free(ftp->dir);

  ftp->file = ftp->dir = NULL; /* zero */

  return retcode;
}

/*
 * ftpsendf() sends the formated string as a ftp command to a ftp server
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 */
size_t Curl_ftpsendf(int fd, struct connectdata *conn,
                     const char *fmt, ...)
{
  size_t bytes_written;
  char s[256];

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(s, 250, fmt, ap);
  va_end(ap);

  if(conn->data->bits.verbose)
    fprintf(conn->data->err, "> %s\n", s);

  strcat(s, "\r\n"); /* append a trailing CRLF */

  bytes_written=0;
  Curl_write(conn, fd, s, strlen(s), &bytes_written);

  return(bytes_written);
}


CURLcode Curl_ftp_disconnect(struct connectdata *conn)
{
  struct FTP *ftp= conn->proto.ftp;

  /* The FTP session may or may not have been allocated/setup at this point! */
  if(ftp) {
    if(ftp->user)
      free(ftp->user);
    if(ftp->passwd)
      free(ftp->passwd);
    if(ftp->entrypath)
      free(ftp->entrypath);
  }
  return CURLE_OK;
}
