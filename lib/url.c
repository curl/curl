/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

/* -- WIN32 approved -- */

#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif
#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#endif

#include "urldata.h"
#include "netrc.h"

#include "formdata.h"
#include "getenv.h"
#include "base64.h"
#include "ssluse.h"
#include "hostip.h"
#include "if2ip.h"
#include "download.h"
#include "sendf.h"
#include "speedcheck.h"
#include "getpass.h"
#include "progress.h"
#include "cookie.h"
#include "strequal.h"
#include "escape.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "http.h"
#include "file.h"
#include "ldap.h"

#include <curl/types.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#ifdef KRB4
#include "security.h"
#endif
/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* -- -- */


CURLcode _urlget(struct UrlData *data);

/* does nothing, returns OK */
CURLcode curl_init(void)
{
  return CURLE_OK;
}

/* does nothing */
void curl_free(void)
{
}

void static urlfree(struct UrlData *data, bool totally)
{
#ifdef USE_SSLEAY
  if (data->ssl.use) {
    if(data->ssl.handle) {
      (void)SSL_shutdown(data->ssl.handle);
      SSL_set_connect_state(data->ssl.handle);

      SSL_free (data->ssl.handle);
      data->ssl.handle = NULL;
    }
    if(data->ssl.ctx) {
      SSL_CTX_free (data->ssl.ctx);
      data->ssl.ctx = NULL;
    }
    data->ssl.use = FALSE; /* get back to ordinary socket usage */
  }
#endif /* USE_SSLEAY */

  /* close possibly still open sockets */
  if(-1 != data->secondarysocket) {
    sclose(data->secondarysocket);
    data->secondarysocket = -1;	
  }
  if(-1 != data->firstsocket) {
    sclose(data->firstsocket);
    data->firstsocket=-1;
  }

  if(data->bits.proxystringalloc) {
    data->bits.proxystringalloc=FALSE;;
    free(data->proxy);
    data->proxy=NULL;

    /* Since we allocated the string the previous round, it means that we
       "discovered" the proxy in the environment variables and thus we must
       switch off that knowledge again... */
    data->bits.httpproxy=FALSE;
  }
  
  if(data->bits.rangestringalloc) {
    free(data->range);
    data->range=NULL;
    data->bits.rangestringalloc=0; /* free now */
  }

  if(data->ptr_proxyuserpwd) {
    free(data->ptr_proxyuserpwd);
    data->ptr_proxyuserpwd=NULL;
  }
  if(data->ptr_uagent) {
    free(data->ptr_uagent);
    data->ptr_uagent=NULL;
  }
  if(data->ptr_userpwd) {
    free(data->ptr_userpwd);
    data->ptr_userpwd=NULL;
  }
  if(data->ptr_rangeline) {
    free(data->ptr_rangeline);
    data->ptr_rangeline=NULL;
  }
  if(data->ptr_ref) {
    free(data->ptr_ref);
    data->ptr_ref=NULL;
  }
  if(data->ptr_cookie) {
    free(data->ptr_cookie);
    data->ptr_cookie=NULL;
  }
  if(data->ptr_host) {
    free(data->ptr_host);
    data->ptr_host=NULL;
  }

  if(totally) {
    /* we let the switch decide whether we're doing a part or total
       cleanup */

    /* check for allocated [URL] memory to free: */
    if(data->freethis)
      free(data->freethis);

    if(data->headerbuff)
      free(data->headerbuff);

    if(data->free_referer)
      free(data->referer);

    if(data->bits.urlstringalloc)
      /* the URL is allocated, free it! */
      free(data->url);

    cookie_cleanup(data->cookies);

    free(data);

    /* global cleanup */
    curl_free();
  }
}

CURLcode curl_close(CURL *curl)
{
  struct UrlData *data=(struct UrlData *)curl;
  
  void *protocol = data->proto.generic;

  /* total session cleanup (frees 'data' as well!)*/
  urlfree(data, TRUE);

  if(protocol)
    free(protocol);

  return CURLE_OK;
}

int my_getpass(void *clientp, char *prompt, char* buffer, int buflen )
{
  char *retbuf;
  retbuf = getpass_r(prompt, buffer, buflen);
  if(NULL == retbuf)
    return 1;
  else
    return 0; /* success */
}


CURLcode curl_open(CURL **curl, char *url)
{
  /* We don't yet support specifying the URL at this point */
  struct UrlData *data;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = (struct UrlData *)malloc(sizeof(struct UrlData));
  if(data) {
    memset(data, 0, sizeof(struct UrlData));
    data->handle = STRUCT_OPEN;
    data->interf = CURLI_NORMAL; /* normal interface by default */

    /* We do some initial setup here, all those fields that can't be just 0 */

    data-> headerbuff=(char*)malloc(HEADERSIZE);
    if(!data->headerbuff) {
      free(data); /* free the memory again */
      return CURLE_OUT_OF_MEMORY;
    }

    data-> headersize=HEADERSIZE;

#if 0
    /* Let's set some default values: */
    curl_setopt(data, CURLOPT_FILE, stdout); /* default output to stdout */
    curl_setopt(data, CURLOPT_INFILE, stdin);  /* default input from stdin */
    curl_setopt(data, CURLOPT_STDERR, stderr);  /* default stderr to stderr! */
#endif

    data->out = stdout; /* default output to stdout */
    data->in  = stdin;  /* default input from stdin */
    data->err  = stderr;  /* default stderr to stderr */

    data->firstsocket = -1; /* no file descriptor */
    data->secondarysocket = -1; /* no file descriptor */

    /* use fwrite as default function to store output */
    data->fwrite = (size_t (*)(char *, size_t, size_t, FILE *))fwrite;

    /* use fread as default function to read input */
    data->fread = (size_t (*)(char *, size_t, size_t, FILE *))fread;

    /* set the default passwd function */
    data->fpasswd = my_getpass;

    data->infilesize = -1; /* we don't know any size */

    data->current_speed = -1; /* init to negative == impossible */

    *curl = data;
    return CURLE_OK;
  }

  /* this is a very serious error */
  return CURLE_OUT_OF_MEMORY;
}

CURLcode curl_setopt(CURL *curl, CURLoption option, ...)
{
  struct UrlData *data = curl;
  va_list param;
  char *cookiefile;

  va_start(param, option);

  switch(option) {
  case CURLOPT_VERBOSE:
    data->bits.verbose = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_HEADER:
    data->bits.http_include_header = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_NOPROGRESS:
    data->bits.hide_progress = va_arg(param, long)?TRUE:FALSE;
    if(data->bits.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    break;
  case CURLOPT_NOBODY:
    data->bits.no_body = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FAILONERROR:
    data->bits.http_fail_on_error = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_UPLOAD:
    data->bits.upload = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_POST:
    data->bits.http_post = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FILETIME:
    data->bits.get_filetime = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FTPLISTONLY:
    data->bits.ftp_list_only = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FTPAPPEND:
    data->bits.ftp_append = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_NETRC:
    data->bits.use_netrc = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FOLLOWLOCATION:
    data->bits.http_follow_location = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FTPASCII:
    data->bits.ftp_ascii = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_PUT:
    data->bits.http_put = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_MUTE:
    data->bits.mute = va_arg(param, long)?TRUE:FALSE;
    break;

  case CURLOPT_TIMECONDITION:
    data->timecondition = va_arg(param, long);
    break;

  case CURLOPT_TIMEVALUE:
    data->timevalue = va_arg(param, long);
    break;

  case CURLOPT_SSLVERSION:
    data->ssl.version = va_arg(param, long);
    break;

  case CURLOPT_COOKIEFILE:
    cookiefile = (char *)va_arg(param, void *);
    if(cookiefile) {
      data->cookies = cookie_init(cookiefile);
    }
    break;
  case CURLOPT_WRITEHEADER:
    data->writeheader = (FILE *)va_arg(param, FILE *);
    break;
  case CURLOPT_COOKIE:
    data->cookie = va_arg(param, char *);
    break;
  case CURLOPT_ERRORBUFFER:
    data->errorbuffer = va_arg(param, char *);
    break;
  case CURLOPT_FILE:
    data->out = va_arg(param, FILE *);
    break;
  case CURLOPT_FTPPORT:
    data->ftpport = va_arg(param, char *);
    data->bits.ftp_use_port = data->ftpport?1:0;
    break;
  case CURLOPT_HTTPHEADER:
    data->headers = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_CUSTOMREQUEST:
    data->customrequest = va_arg(param, char *);
    break;
  case CURLOPT_HTTPPOST:
    data->httppost = va_arg(param, struct HttpPost *);
    data->bits.http_formpost = data->httppost?1:0;
    break;
  case CURLOPT_INFILE:
    data->in = va_arg(param, FILE *);
    break;
  case CURLOPT_INFILESIZE:
    data->infilesize = va_arg(param, long);
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    data->low_speed_limit=va_arg(param, long);
    break;
  case CURLOPT_LOW_SPEED_TIME:
    data->low_speed_time=va_arg(param, long);
    break;
  case CURLOPT_URL:
    data->url = va_arg(param, char *);
    break;
  case CURLOPT_PORT:
    data->port = va_arg(param, long);
    break;
  case CURLOPT_POSTFIELDS:
    data->postfields = va_arg(param, char *);
    break;
  case CURLOPT_POSTFIELDSIZE:
    data->postfieldsize = va_arg(param, long);
    break;
  case CURLOPT_REFERER:
    data->referer = va_arg(param, char *);
    data->bits.http_set_referer = (data->referer && *data->referer)?1:0;
    break;
  case CURLOPT_AUTOREFERER:
    data->bits.http_auto_referer = va_arg(param, long)?1:0;
    break;
  case CURLOPT_PROXY:
    data->proxy = va_arg(param, char *);
    data->bits.httpproxy = data->proxy?1:0;
    break;
  case CURLOPT_HTTPPROXYTUNNEL:
    data->bits.tunnel_thru_httpproxy = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_PROXYPORT:
    data->proxyport = va_arg(param, long);
    break;
  case CURLOPT_TIMEOUT:
    data->timeout = va_arg(param, long);
    break;
  case CURLOPT_MAXREDIRS:
    data->maxredirs = va_arg(param, long);
    break;
  case CURLOPT_USERAGENT:
    data->useragent = va_arg(param, char *);
    break;
  case CURLOPT_USERPWD:
    data->userpwd = va_arg(param, char *);
    data->bits.user_passwd = data->userpwd?1:0;
    break;
  case CURLOPT_POSTQUOTE:
    data->postquote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_PROGRESSFUNCTION:
    data->fprogress = va_arg(param, curl_progress_callback);
    data->progress.callback = TRUE; /* no longer internal */
    break;
  case CURLOPT_PROGRESSDATA:
    data->progress_client = va_arg(param, void *);
    break;
  case CURLOPT_PASSWDFUNCTION:
    data->fpasswd = va_arg(param, curl_passwd_callback);
    break;
  case CURLOPT_PASSWDDATA:
    data->passwd_client = va_arg(param, void *);
    break;
  case CURLOPT_PROXYUSERPWD:
    data->proxyuserpwd = va_arg(param, char *);
    data->bits.proxy_user_passwd = data->proxyuserpwd?1:0;
    break;
  case CURLOPT_RANGE:
    data->range = va_arg(param, char *);
    data->bits.set_range = data->range?1:0;
    break;
  case CURLOPT_RESUME_FROM:
    data->resume_from = va_arg(param, long);
    break;
  case CURLOPT_STDERR:
    data->err = va_arg(param, FILE *);
    break;
  case CURLOPT_WRITEFUNCTION:
    data->fwrite = va_arg(param, curl_write_callback);
    break;
#if 0
  case CURLOPT_WRITEINFO:
    data->writeinfo = va_arg(param, char *);
    break;
#endif
  case CURLOPT_READFUNCTION:
    data->fread = va_arg(param, curl_read_callback);
    break;
  case CURLOPT_SSLCERT:
    data->cert = va_arg(param, char *);
    break;
  case CURLOPT_SSLCERTPASSWD:
    data->cert_passwd = va_arg(param, char *);
    break;
  case CURLOPT_CRLF:
    data->crlf = va_arg(param, long);
    break;
  case CURLOPT_QUOTE:
    data->quote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_INTERFACE:
    data->device = va_arg(param, char *);
    break;
  case CURLOPT_KRB4LEVEL:
    data->krb4_level = va_arg(param, char *);
    data->bits.krb4=data->krb4_level?TRUE:FALSE;
    break;
  case CURLOPT_SSL_VERIFYPEER:
    data->ssl.verifypeer = va_arg(param, long);
    break;
  case CURLOPT_CAINFO:
    data->ssl.CAfile = va_arg(param, char *);
    data->ssl.CApath = NULL; /*This does not work on windows.*/
    break;
  default:
    /* unknown tag and its companion, just ignore: */
    return CURLE_READ_ERROR; /* correct this */
  }
  return CURLE_OK;
}


/*
 * Read everything until a newline.
 */

int GetLine(int sockfd, char *buf, struct UrlData *data)
{
  int nread;
  int read_rc=1;
  char *ptr;
  ptr=buf;

  /* get us a full line, terminated with a newline */
  for(nread=0;
      (nread<BUFSIZE) && read_rc;
      nread++, ptr++) {
#ifdef USE_SSLEAY
    if (data->ssl.use) {
      read_rc = SSL_read(data->ssl.handle, ptr, 1);
    }
    else {
#endif
      read_rc = sread(sockfd, ptr, 1);
#ifdef USE_SSLEAY
    }
#endif /* USE_SSLEAY */
    if (*ptr == '\n')
      break;
  }
  *ptr=0; /* zero terminate */

  if(data->bits.verbose) {
    fputs("< ", data->err);
    fwrite(buf, 1, nread, data->err);
    fputs("\n", data->err);
  }
  return nread;
}


#ifndef WIN32
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
RETSIGTYPE alarmfunc(int signal)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)signal;
  return;
}
#endif

CURLcode curl_write(CURLconnect *c_conn, char *buf, size_t amount,
                   size_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  struct UrlData *data;
  size_t bytes_written;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return CURLE_FAILED_INIT;
  data = conn->data;

#ifdef USE_SSLEAY
  if (data->ssl.use) {
    bytes_written = SSL_write(data->ssl.handle, buf, amount);
  }
  else {
#endif
#ifdef KRB4
    if(conn->sec_complete)
      bytes_written = sec_write(conn, conn->writesockfd, buf, amount);
    else
#endif
      bytes_written = swrite(conn->writesockfd, buf, amount);
#ifdef USE_SSLEAY
  }
#endif /* USE_SSLEAY */

  *n = bytes_written;
  return CURLE_OK;
}

CURLcode curl_read(CURLconnect *c_conn, char *buf, size_t buffersize,
                   size_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  struct UrlData *data;
  size_t nread;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return CURLE_FAILED_INIT;
  data = conn->data;

#ifdef USE_SSLEAY
  if (data->ssl.use) {
    nread = SSL_read (data->ssl.handle, buf, buffersize);
  }
  else {
#endif
#ifdef KRB4
    if(conn->sec_complete)
      nread = sec_read(conn, conn->sockfd, buf, buffersize);
    else
#endif
      nread = sread (conn->sockfd, buf, buffersize);
#ifdef USE_SSLEAY
  }
#endif /* USE_SSLEAY */
  *n = nread;
  return CURLE_OK;
}

CURLcode curl_disconnect(CURLconnect *c_connect)
{
  struct connectdata *conn = c_connect;

  struct UrlData *data = conn->data;

  if(conn->hostent_buf) /* host name info */
    free(conn->hostent_buf);

  if(conn->path) /* the URL path part */
    free(conn->path);

  free(conn); /* free the connection oriented data */

  /* clean up the sockets and SSL stuff from the previous "round" */
  urlfree(data, FALSE);

  return CURLE_OK;
}

static CURLcode _connect(CURL *curl, CURLconnect **in_connect)
{
  char *tmp;
  char *buf;
  CURLcode result;
  char resumerange[40]="";
  struct UrlData *data = curl;
  struct connectdata *conn;
#ifdef HAVE_SIGACTION
  struct sigaction sigact;
#endif
  int urllen;

  if(!data || (data->handle != STRUCT_OPEN))
    return CURLE_BAD_FUNCTION_ARGUMENT; /* TBD: make error codes */

  if(!data->url)
    return CURLE_URL_MALFORMAT;

  conn = (struct connectdata *)malloc(sizeof(struct connectdata));
  if(!conn) {
    *in_connect = NULL; /* clear the pointer */
    return CURLE_OUT_OF_MEMORY;
  }
  *in_connect = conn;

  memset(conn, 0, sizeof(struct connectdata));
  conn->handle = STRUCT_CONNECT;

  conn->data = data; /* remember our daddy */
  conn->state = CONN_INIT;

  conn->upload_bufsize = UPLOAD_BUFSIZE; /* the smallest upload buffer size
                                            we use */

  buf = data->buffer; /* this is our buffer */

#ifdef HAVE_SIGACTION
  sigaction(SIGALRM, NULL, &sigact);
  sigact.sa_handler = alarmfunc;
  sigact.sa_flags &= ~SA_RESTART;
  sigaction(SIGALRM, &sigact, NULL);
#else
  /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
  signal(SIGALRM, alarmfunc);
#endif

#endif

  /* We need to allocate memory to store the path in. We get the size of the
     full URL to be sure, and we need to make it at least 256 bytes since
     other parts of the code will rely on this fact */
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;
  
  conn->path=(char *)malloc(urllen);
  if(NULL == conn->path)
    return CURLE_OUT_OF_MEMORY; /* really bad error */

  /* Parse <url> */
  /* We need to parse the url, even when using the proxy, because
   * we will need the hostname and port in case we are trying
   * to SSL connect through the proxy -- and we don't know if we
   * will need to use SSL until we parse the url ...
   */
  if((2 == sscanf(data->url, "%64[^:]://%[^\n]",
                  conn->proto,
                  conn->path)) && strequal(conn->proto, "file")) {
    /* we deal with file://<host>/<path> differently since it
       supports no hostname other than "localhost" and "127.0.0.1",
       which is unique among the protocols specified in RFC 1738 */
    if (strnequal(conn->path, "localhost/", 10) ||
        strnequal(conn->path, "127.0.0.1/", 10))
      /* ... since coincidentally both host strings are of equal length
         otherwise, <host>/ is quietly ommitted */
      strcpy(conn->path, &conn->path[10]);

    strcpy(conn->proto, "file");
  }
  else {
    /* Set default host and default path */
    strcpy(conn->gname, "curl.haxx.se");
    strcpy(conn->path, "/");

    if (2 > sscanf(data->url,
                   "%64[^\n:]://%256[^\n/]%[^\n]",
                   conn->proto, conn->gname, conn->path)) {
      
      /* badly formatted, let's try the browser-style _without_ 'http://' */
      if((1 > sscanf(data->url, "%256[^\n/]%[^\n]",
                     conn->gname, conn->path)) ) {
        failf(data, "<url> malformed");
        return CURLE_URL_MALFORMAT;
      }
      if(strnequal(conn->gname, "FTP", 3)) {
        strcpy(conn->proto, "ftp");
      }
      else if(strnequal(conn->gname, "GOPHER", 6))
        strcpy(conn->proto, "gopher");
#ifdef USE_SSLEAY
      else if(strnequal(conn->gname, "HTTPS", 5))
        strcpy(conn->proto, "https");
#endif /* USE_SSLEAY */
      else if(strnequal(conn->gname, "TELNET", 6))
        strcpy(conn->proto, "telnet");
      else if (strnequal(conn->gname, "DICT", sizeof("DICT")-1))
        strcpy(conn->proto, "DICT");
      else if (strnequal(conn->gname, "LDAP", sizeof("LDAP")-1))
        strcpy(conn->proto, "LDAP");
      else {
        strcpy(conn->proto, "http");
      }

      conn->protocol |= PROT_MISSING; /* not given in URL */
    }
  }


  if(data->bits.user_passwd && !data->bits.use_netrc) {
    data->user[0] =0;
    data->passwd[0]=0;

    if(*data->userpwd != ':') {
      /* the name is given, get user+password */
      sscanf(data->userpwd, "%127[^:]:%127[^\n]",
             data->user, data->passwd);
      }
    else
      /* no name given, get the password only */
      sscanf(data->userpwd+1, "%127[^\n]", data->passwd);

    /* check for password, if no ask for one */
    if( !data->passwd[0] ) {
      if(!data->fpasswd ||
         data->fpasswd(data->passwd_client,
                       "password:", data->passwd, sizeof(data->passwd)))
        return CURLE_BAD_PASSWORD_ENTERED;
    }
  }

  if(data->bits.proxy_user_passwd) {
    data->proxyuser[0] =0;
    data->proxypasswd[0]=0;

    if(*data->proxyuserpwd != ':') {
      /* the name is given, get user+password */
      sscanf(data->proxyuserpwd, "%127[^:]:%127[^\n]",
             data->proxyuser, data->proxypasswd);
      }
    else
      /* no name given, get the password only */
      sscanf(data->proxyuserpwd+1, "%127[^\n]", data->proxypasswd);

    /* check for password, if no ask for one */
    if( !data->proxypasswd[0] ) {
      if(!data->fpasswd ||
         data->fpasswd( data->passwd_client,
                        "proxy password:",
                        data->proxypasswd,
                        sizeof(data->proxypasswd)))
        return CURLE_BAD_PASSWORD_ENTERED;
    }

  }

  conn->name = conn->gname;
  conn->ppath = conn->path;
  data->hostname = conn->name;


  if(!data->bits.httpproxy) {
    /* If proxy was not specified, we check for default proxy environment
       variables, to enable i.e Lynx compliance:

       http_proxy=http://some.server.dom:port/
       https_proxy=http://some.server.dom:port/
       ftp_proxy=http://some.server.dom:port/
       gopher_proxy=http://some.server.dom:port/
       no_proxy=domain1.dom,host.domain2.dom
                                 (a comma-separated list of hosts which should
                                  not be proxied, or an asterisk to override
                                  all proxy variables)
       all_proxy=http://some.server.dom:port/
                                 (seems to exist for the CERN www lib. Probably
                                  the first to check for.)

       For compatibility, the all-uppercase versions of these variables are
       checked if the lowercase versions don't exist.
       */
    char *no_proxy=NULL;
    char *proxy=NULL;
    char proxy_env[128];

    no_proxy=GetEnv("no_proxy");
    if(!no_proxy)
      no_proxy=GetEnv("NO_PROXY");

    if(!no_proxy || !strequal("*", no_proxy)) {
      /* NO_PROXY wasn't specified or it wasn't just an asterisk */
      char *nope;

      nope=no_proxy?strtok(no_proxy, ", "):NULL;
      while(nope) {
        if(strlen(nope) <= strlen(conn->name)) {
          char *checkn=
            conn->name + strlen(conn->name) - strlen(nope);
          if(strnequal(nope, checkn, strlen(nope))) {
            /* no proxy for this host! */
            break;
          }
        }
	nope=strtok(NULL, ", ");
      }
      if(!nope) {
	/* It was not listed as without proxy */
	char *protop = conn->proto;
	char *envp = proxy_env;
	char *prox;

	/* Now, build <protocol>_proxy and check for such a one to use */
	while(*protop)
	  *envp++ = tolower(*protop++);

	/* append _proxy */
	strcpy(envp, "_proxy");

	/* read the protocol proxy: */
	prox=GetEnv(proxy_env);

	if(!prox) {
          /* There was no lowercase variable, try the uppercase version: */
	  for(envp = proxy_env; *envp; envp++)
	    *envp = toupper(*envp);
	  prox=GetEnv(proxy_env);
	}

	if(prox && *prox) { /* don't count "" strings */
	  proxy = prox; /* use this */
	}
	else {
	  proxy = GetEnv("all_proxy"); /* default proxy to use */
	  if(!proxy)
            proxy=GetEnv("ALL_PROXY");
	}

        if(proxy && *proxy) {
          /* we have a proxy here to set */
          data->proxy = proxy;
          data->bits.proxystringalloc=1; /* this needs to be freed later */
          data->bits.httpproxy=1;
        }
      } /* if (!nope) - it wasn't specified non-proxy */
    } /* NO_PROXY wasn't specified or '*' */
    if(no_proxy)
      free(no_proxy);
  } /* if not using proxy */

  if((conn->protocol&PROT_MISSING) && data->bits.httpproxy ) {
    /* We're guessing prefixes here and since we're told to use a proxy, we
       need to add the protocol prefix to the URL string before we continue!
       */
    char *reurl;

    reurl = maprintf("%s://%s", conn->proto, data->url);

    if(!reurl)
      return CURLE_OUT_OF_MEMORY;

    data->url = reurl;
    if(data->freethis)
      free(data->freethis);
    data->freethis = reurl;

    conn->protocol &= ~PROT_MISSING; /* switch that one off again */
  }

  /* RESUME on a HTTP page is a tricky business. First, let's just check that
     'range' isn't used, then set the range parameter and leave the resume as
     it is to inform about this situation for later use. We will then
     "attempt" to resume, and if we're talking to a HTTP/1.1 (or later)
     server, we will get the document resumed. If we talk to a HTTP/1.0
     server, we just fail since we can't rewind the file writing from within
     this function. */
  if(data->resume_from) {
    if(!data->bits.set_range) {
      /* if it already was in use, we just skip this */
      snprintf(resumerange, sizeof(resumerange), "%d-", data->resume_from);
      data->range=strdup(resumerange); /* tell ourselves to fetch this range */
      data->bits.rangestringalloc = TRUE; /* mark as allocated */
      data->bits.set_range = 1; /* switch on range usage */
    }
  }


  if(data->timeout) {
    /* We set the timeout on the connection/resolving phase first, separately
       from the download/upload part to allow a maximum time on everything */
    myalarm(data->timeout); /* this sends a signal when the timeout fires
			       off, and that will abort system calls */
  }

  /*
   * Hmm, if we are using a proxy, then we can skip the GOPHER and the
   * FTP steps, although we cannot skip the HTTPS step (since the proxy
   * works differently, depending on whether its SSL or not).
   */

  if (strequal(conn->proto, "HTTP")) {
    if(!data->port)
      data->port = PORT_HTTP;
    data->remote_port = PORT_HTTP;
    conn->protocol |= PROT_HTTP;
    conn->curl_do = http;
    conn->curl_done = http_done;
    conn->curl_close = http_close;
  }
  else if (strequal(conn->proto, "HTTPS")) {
#ifdef USE_SSLEAY
    if(!data->port)
      data->port = PORT_HTTPS;
    data->remote_port = PORT_HTTPS;
    conn->protocol |= PROT_HTTP;
    conn->protocol |= PROT_HTTPS;

    conn->curl_do = http;
    conn->curl_done = http_done;
    conn->curl_connect = http_connect;
    conn->curl_close = http_close;

#else /* USE_SSLEAY */
    failf(data, "libcurl was built with SSL disabled, https: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
  }
  else if (strequal(conn->proto, "GOPHER")) {
    if(!data->port)
      data->port = PORT_GOPHER;
    data->remote_port = PORT_GOPHER;
    /* Skip /<item-type>/ in path if present */
    if (isdigit((int)conn->path[1])) {
      conn->ppath = strchr(&conn->path[1], '/');
      if (conn->ppath == NULL)
	conn->ppath = conn->path;
      }
    conn->protocol |= PROT_GOPHER;
    conn->curl_do = http;
    conn->curl_done = http_done;
    conn->curl_close = http_close;
  }
  else if(strequal(conn->proto, "FTP")) {
    char *type;
    if(!data->port)
      data->port = PORT_FTP;
    data->remote_port = PORT_FTP;
    conn->protocol |= PROT_FTP;

    if(data->bits.httpproxy &&
       !data->bits.tunnel_thru_httpproxy) {
      /* Unless we have asked to tunnel ftp operations through the proxy, we
         switch and use HTTP operations only */
      conn->curl_do = http;
      conn->curl_done = http_done;
      conn->curl_close = http_close;
    }
    else {
      conn->curl_do = ftp;
      conn->curl_done = ftp_done;
      conn->curl_connect = ftp_connect;
    }

    conn->ppath++; /* don't include the initial slash */

    /* FTP URLs support an extension like ";type=<typecode>" that
       we'll try to get now! */
    type=strstr(conn->ppath, ";type=");
    if(!type) {
      type=strstr(conn->gname, ";type=");
    }
    if(type) {
      char command;
      *type=0;
      command = toupper(type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
	data->bits.ftp_ascii = 1;
	break;
      case 'D': /* directory mode */
	data->bits.ftp_list_only = 1;
	break;
      case 'I': /* binary mode */
      default:
	/* switch off ASCII */
	data->bits.ftp_ascii = 0;
	break;
      }
    }
  }
  else if(strequal(conn->proto, "TELNET")) {
    /* telnet testing factory */
    conn->protocol |= PROT_TELNET;
    if(!data->port)
      data->port = PORT_TELNET;
    data->remote_port = PORT_TELNET;

    conn->curl_do = telnet;
    conn->curl_done = telnet_done;

  }
  else if (strequal(conn->proto, "DICT")) {
    conn->protocol |= PROT_DICT;
    if(!data->port)
      data->port = PORT_DICT;
    data->remote_port = PORT_DICT;
    conn->curl_do = dict;
    conn->curl_done = dict_done;
  }
  else if (strequal(conn->proto, "LDAP")) {
    conn->protocol |= PROT_LDAP;
    if(!data->port)
      data->port = PORT_LDAP;
    data->remote_port = PORT_LDAP;
    conn->curl_do = ldap;
    conn->curl_done = ldap_done;
  }
  else if (strequal(conn->proto, "FILE")) {
    conn->protocol |= PROT_FILE;

    conn->curl_do = file;
    /* no done() function */

    result = Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                      -1, NULL); /* no upload */

    return CURLE_OK;
  }

  else {
    failf(data, "Unsupported protocol: %s", conn->proto);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  if(data->bits.use_netrc) {
    if(ParseNetrc(data->hostname, data->user, data->passwd)) {
      infof(data, "Couldn't find host %s in the .netrc file, using defaults",
            data->hostname);
    }
    /* weather we failed or not, we don't know which fields that were filled
       in anyway */
    if(!data->user[0])
      strcpy(data->user, CURL_DEFAULT_USER);
    if(!data->passwd[0])
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    if(conn->protocol&PROT_HTTP) {
      data->bits.user_passwd = 1; /* enable user+password */
    }
  }
  else if(!(data->bits.user_passwd) &&
	  (conn->protocol & (PROT_FTP|PROT_HTTP)) ) {
    /* This is a FTP or HTTP URL, and we haven't got the user+password in
       the extra parameter, we will now try to extract the possible
       user+password pair in a string like:
       ftp://user:password@ftp.my.site:8021/README */
    char *ptr=NULL; /* assign to remove possible warnings */
#if 0
    if(':' == *conn->name) {
      failf(data, "URL malformat: user can't be zero length");
      return CURLE_URL_MALFORMAT_USER;
    }
#endif
    if((ptr=strchr(conn->name, '@'))) {
      /* there's a user+password given here, to the left of the @ */

      data->user[0] =0;
      data->passwd[0]=0;

      if(*conn->name != ':') {
        /* the name is given, get user+password */
        sscanf(conn->name, "%127[^:@]:%127[^@]",
               data->user, data->passwd);
      }
      else
        /* no name given, get the password only */
        sscanf(conn->name+1, "%127[^@]", data->passwd);

      if(data->user[0]) {
        char *newname=curl_unescape(data->user, 0);
        if(strlen(newname) < sizeof(data->user)) {
          strcpy(data->user, newname);
        }
        /* if the new name is longer than accepted, then just use
           the unconverted name, it'll be wrong but what the heck */
        free(newname);
      }

      /* check for password, if no ask for one */
      if( !data->passwd[0] ) {
        if(!data->fpasswd ||
           data->fpasswd(data->passwd_client,
                         "password:",data->passwd,sizeof(data->passwd)))
          return CURLE_BAD_PASSWORD_ENTERED;
      }
      else {
        /* we have a password found in the URL, decode it! */
        char *newpasswd=curl_unescape(data->passwd, 0);
        if(strlen(newpasswd) < sizeof(data->passwd)) {
          strcpy(data->passwd, newpasswd);
        }
        free(newpasswd);
      }

      conn->name = ++ptr;
      data->bits.user_passwd=1; /* enable user+password */
    }
    else {
      strcpy(data->user, CURL_DEFAULT_USER);
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    }
  }

  if(!data->bits.httpproxy) {
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    tmp = strchr(conn->name, ':');
    if (tmp) {
      *tmp++ = '\0';
      data->port = atoi(tmp);
    }
    data->remote_port = data->port; /* it is the same port */

    /* Connect to target host right on */
    conn->hp = GetHost(data, conn->name, &conn->hostent_buf);
    if(!conn->hp) {
      failf(data, "Couldn't resolve host '%s'", conn->name);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }
  else {
    char *prox_portno;
    char *endofprot;

    /* We need to make a duplicate of the proxy so that we can modify the
       string safely. */
    char *proxydup=strdup(data->proxy);

    /* We use 'proxyptr' to point to the proxy name from now on... */
    char *proxyptr=proxydup;

    if(NULL == proxydup) {
      failf(data, "memory shortage");
      return CURLE_OUT_OF_MEMORY;
    }

    /* we use proxy all right, but we wanna know the remote port for SSL
       reasons */
    tmp = strchr(conn->name, ':');
    if (tmp) {
      *tmp++ = '\0'; /* cut off the name there */
      data->remote_port = atoi(tmp);
    }

    /* Daniel Dec 10, 1998:
       We do the proxy host string parsing here. We want the host name and the
       port name. Accept a protocol:// prefix, even though it should just be
       ignored. */

    /* 1. skip the protocol part if present */
    endofprot=strstr(proxyptr, "://");
    if(endofprot) {
      proxyptr = endofprot+3;
    }

    /* allow user to specify proxy.server.com:1080 if desired */
    prox_portno = strchr (proxyptr, ':');
    if (prox_portno) {
      *prox_portno = 0x0; /* cut off number from host name */
      prox_portno ++;
      /* now set the local port number */
      data->port = atoi(prox_portno);
    }
    else if(data->proxyport) {
      /* None given in the proxy string, then get the default one if it is
         given */
      data->port = data->proxyport;
    }

    /* connect to proxy */
    conn->hp = GetHost(data, proxyptr, &conn->hostent_buf);
    if(!conn->hp) {
      failf(data, "Couldn't resolve proxy '%s'", proxyptr);
      return CURLE_COULDNT_RESOLVE_PROXY;
    }

    free(proxydup); /* free the duplicate pointer and not the modified */
  }
  pgrsTime(data, TIMER_NAMELOOKUP);

  data->firstsocket = socket(AF_INET, SOCK_STREAM, 0);

  memset((char *) &conn->serv_addr, '\0', sizeof(conn->serv_addr));
  memcpy((char *)&(conn->serv_addr.sin_addr),
         conn->hp->h_addr, conn->hp->h_length);
  conn->serv_addr.sin_family = conn->hp->h_addrtype;
  conn->serv_addr.sin_port = htons(data->port);

#ifndef WIN32 
  /* We don't generally like checking for OS-versions, we should make this
     HAVE_XXXX based, although at the moment I don't have a decent test for
     this! */

  /* sck 8/31/2000 add support for specifing device to bind socket to */
  /* I am using this, but it may not work everywhere, only tested on
     RedHat 6.2 */
#ifdef HAVE_INET_NTOA

#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif

  if (data->device && (strlen(data->device)<255)) {
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    char *hostdataptr=NULL;
    size_t size;
    char myhost[256] = "";
    unsigned long in;

    if(if2ip(data->device, myhost, sizeof(myhost))) {
      h = GetHost(data, myhost, &hostdataptr);
    }
    else {
      if(strlen(data->device)>1) {
        h = GetHost(data, data->device, &hostdataptr);
      }
      if(h) {
        /* we know data->device is shorter than the myhost array */
        strcpy(myhost, data->device);
      }
    }

    if(! *myhost) {
      /* need to fix this
         h=GetHost(data,
         getmyhost(*myhost,sizeof(myhost)),
         hostent_buf,
         sizeof(hostent_buf));
      */
      printf("in here\n");
    }

    infof(data, "We connect from %s\n", myhost);

    if ( (in=inet_addr(myhost)) != INADDR_NONE ) {

      if ( h ) {
        memset((char *)&sa, 0, sizeof(sa));
        memcpy((char *)&sa.sin_addr,
               h->h_addr,
               h->h_length);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = in;
        sa.sin_port = 0; /* get any port */
	
        if( bind(data->firstsocket, (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
          /* we succeeded to bind */
          struct sockaddr_in add;
	
          size = sizeof(add);
          if(getsockname(data->firstsocket, (struct sockaddr *) &add,
                         (int *)&size)<0) {
            failf(data, "getsockname() failed");
            return CURLE_HTTP_PORT_FAILED;
          }
        }
        else {
          switch(errno) {
          case EBADF:
            failf(data, "Invalid descriptor: %d", errno);
            break;
          case EINVAL:
            failf(data, "Invalid request: %d", errno);
            break;
          case EACCES:
            failf(data, "Address is protected, user not superuser: %d", errno);
            break;
          case ENOTSOCK:
            failf(data,
                  "Argument is a descriptor for a file, not a socket: %d",
                  errno);
            break;
          case EFAULT:
            failf(data, "Inaccessable memory error: %d", errno);
            break;
          case ENAMETOOLONG:
            failf(data, "Address too long: %d", errno);
            break;
          case ENOMEM:
            failf(data, "Insufficient kernel memory was available: %d", errno);
            break;
#if 0
          case EROFS:
            failf(data,
                  "Socket inode would reside on a read-only file system: %d",
                  errno);
            break;
          case ENOENT:
            failf(data, "File does not exist: %d", errno);
            break;
          case ENOTDIR:
            failf(data, "Component of path prefix is not a directory: %d",
                  errno);
            break;
          case ELOOP:
            failf(data,"Too many symbolic links encountered: %d",errno);
            break;
#endif
          default:
            failf(data,"errno %d\n");
          } /* end of switch */
	
          return CURLE_HTTP_PORT_FAILED;
        } /* end of else */
	
      } /* end of if  h */
      else {
	failf(data,"could't find my own IP address (%s)", myhost);
	return CURLE_HTTP_PORT_FAILED;
      }
    } /* end of inet_addr */

    else {
      failf(data, "could't find my own IP address (%s)", myhost);
      return CURLE_HTTP_PORT_FAILED;
    }

    if(hostdataptr)
      free(hostdataptr); /* allocated by GetHost() */

  } /* end of device selection support */
#endif  /* end of HAVE_INET_NTOA */
#endif /* end of not WIN32 */

  if (connect(data->firstsocket,
              (struct sockaddr *) &(conn->serv_addr),
              sizeof(conn->serv_addr)
              ) < 0) {
    switch(errno) {
#ifdef ECONNREFUSED
      /* this should be made nicer */
    case ECONNREFUSED:
      failf(data, "Connection refused");
      break;
    case EFAULT:
      failf(data, "Invalid socket address: %d",errno);
      break;
    case EISCONN:
      failf(data, "Socket already connected: %d",errno);
      break;
    case ETIMEDOUT:
      failf(data, "Timeout while accepting connection, server busy: %d",errno);
      break;
    case ENETUNREACH:
      failf(data, "Network is unreachable: %d",errno);
      break;
    case EADDRINUSE:
      failf(data, "Local address already in use: %d",errno);
      break;
    case EINPROGRESS:
      failf(data, "Socket is nonblocking and connection can not be completed immediately: %d",errno);
      break;
    case EALREADY:
      failf(data, "Socket is nonblocking and a previous connection attempt not completed: %d",errno);
      break;
    case EAGAIN:
      failf(data, "No more free local ports: %d",errno);
      break;
    case EACCES:
    case EPERM:
      failf(data, "Attempt to connect to broadcast address without socket broadcast flag or local firewall rule violated: %d",errno);
      break;
#endif
    case EINTR:
      failf(data, "Connection timeouted");
      break;
#if 0
    case EAFNOSUPPORT:
      failf(data, "Incorrect address family: %d",errno);
      break;
    case ENOTSOCK:
      failf(data, "File descriptor is not a socket: %d",errno);
      break;
    case EBADF:
      failf(data, "File descriptor is not a valid index in descriptor table: %d",errno);
      break;
#endif
    default:
      failf(data, "Can't connect to server: %d", errno);
      break;
    }
    return CURLE_COULDNT_CONNECT;
  }

  if(data->bits.proxy_user_passwd) {
    char *authorization;
    snprintf(data->buffer, BUFSIZE, "%s:%s",
             data->proxyuser, data->proxypasswd);
    if(base64_encode(data->buffer, strlen(data->buffer),
                    &authorization) >= 0) {
      data->ptr_proxyuserpwd =
        maprintf("Proxy-authorization: Basic %s\015\012", authorization);
      free(authorization);
    }
  }
  if((conn->protocol&PROT_HTTP) || data->bits.httpproxy) {
    if(data->useragent) {
      data->ptr_uagent = maprintf("User-Agent: %s\015\012", data->useragent);
    }
  }

  if(conn->curl_connect) {
    /* is there a connect() procedure? */
    conn->now = tvnow(); /* set this here for timeout purposes in the
                            connect procedure, it is later set again for the
                            progress meter purpose */
    result = conn->curl_connect(conn);
    if(result != CURLE_OK)
      return result; /* pass back errors */
  }

  pgrsTime(data, TIMER_CONNECT); /* we're connected */

  conn->now = tvnow(); /* time this *after* the connect is done */
  conn->bytecount = 0;
  
  /* Figure out the ip-number and the first host name it shows: */
  {
    struct in_addr in;
    (void) memcpy(&in.s_addr, *conn->hp->h_addr_list, sizeof (in.s_addr));
    infof(data, "Connected to %s (%s)\n", conn->hp->h_name, inet_ntoa(in));
  }

#if 0 /* Kerberos experiements! Beware! Take cover! */
  kerberos_connect(data, name);
#endif

#ifdef __EMX__
  /* 20000330 mgs
   * the check is quite a hack...
   * we're calling _fsetmode to fix the problem with fwrite converting newline
   * characters (you get mangled text files, and corrupted binary files when
   * you download to stdout and redirect it to a file). */

  if ((data->out)->_handle == NULL) {
    _fsetmode(stdout, "b");
  }
#endif

  return CURLE_OK;
}

CURLcode curl_connect(CURL *curl, CURLconnect **in_connect)
{
  CURLcode code;
  struct connectdata *conn;

  /* call the stuff that needs to be called */
  code = _connect(curl, in_connect);

  if(CURLE_OK != code) {
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    conn = (struct connectdata *)*in_connect;
    if(conn) {
      if(conn->path)
        free(conn->path);
      if(conn->hostent_buf)
        free(conn->hostent_buf);
      free(conn);
      *in_connect=NULL;
    }
  }
  return code;
}


/*
 * NAME curl_connect()
 *
 * DESCRIPTION
 *
 * Connects to the peer server and performs the initial setup. This function
 * writes a connect handle to its second argument that is a unique handle for
 * this connect. This allows multiple connects from the same handle returned
 * by curl_open().
 *
 * EXAMPLE
 *
 * CURLCode result;
 * CURL curl;
 * CURLconnect connect;
 * result = curl_connect(curl, &connect);
 */




CURLcode curl_done(CURLconnect *c_connect)
{
  struct connectdata *conn = c_connect;
  struct UrlData *data;
  CURLcode result;

  if(!conn || (conn->handle!= STRUCT_CONNECT)) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(conn->state != CONN_DO) {
    /* This can only be called after a curl_do() */
    return CURLE_BAD_CALLING_ORDER;
  }
  data = conn->data;

  /* this calls the protocol-specific function pointer previously set */
  if(conn->curl_done)
    result = conn->curl_done(conn);
  else
    result = CURLE_OK;

  pgrsDone(data); /* done with the operation */

  conn->state = CONN_DONE;

  return result;
}

CURLcode curl_do(CURLconnect *in_conn)
{
  struct connectdata *conn = in_conn;
  CURLcode result;

  if(!conn || (conn->handle!= STRUCT_CONNECT)) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(conn->state != CONN_INIT) {
    return CURLE_BAD_CALLING_ORDER;
  }

  if(conn->curl_do) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->curl_do(conn);
    if(result) {
      conn->state = CONN_ERROR;
      return result;
    }
  }

  conn->state = CONN_DO; /* we have entered this state */

#if 0
  if(conn->bytecount) {
    double ittook = tvdiff (tvnow(), conn->now);
    infof(data, "%i bytes transfered in %.3lf seconds (%.0lf bytes/sec).\n",
          conn->bytecount, ittook, (double)conn->bytecount/(ittook!=0.0?ittook:1));
  }
#endif
  return CURLE_OK;
}

