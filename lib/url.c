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
#include "base64.h"
#include "ssluse.h"
#include "hostip.h"
#include "if2ip.h"
#include "transfer.h"
#include "sendf.h"
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

/* Local static prototypes */
static int ConnectionKillOne(struct UrlData *data);
static bool ConnectionExists(struct UrlData *data,
                             struct connectdata *needle,
                             struct connectdata **usethis);
static unsigned int ConnectionStore(struct UrlData *data,
                                    struct connectdata *conn);


CURLcode Curl_close(CURL *curl)
{
  struct UrlData *data=(struct UrlData *)curl;
  
  /* Loop through all open connections and kill them one by one */
  while(-1 != ConnectionKillOne(data));

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

  Curl_cookie_cleanup(data->cookies);

  /* free the connection cache */
  free(data->connects);

  free(data);
  return CURLE_OK;
}

static
int my_getpass(void *clientp, char *prompt, char* buffer, int buflen )
{
  char *retbuf;
  retbuf = getpass_r(prompt, buffer, buflen);
  if(NULL == retbuf)
    return 1;
  else
    return 0; /* success */
}


CURLcode Curl_open(CURL **curl, char *url)
{
  /* We don't yet support specifying the URL at this point */
  struct UrlData *data;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = (struct UrlData *)malloc(sizeof(struct UrlData));
  if(data) {
    memset(data, 0, sizeof(struct UrlData));

    /* We do some initial setup here, all those fields that can't be just 0 */

    data-> headerbuff=(char*)malloc(HEADERSIZE);
    if(!data->headerbuff) {
      free(data); /* free the memory again */
      return CURLE_OUT_OF_MEMORY;
    }

    data->headersize=HEADERSIZE;

    data->out = stdout; /* default output to stdout */
    data->in  = stdin;  /* default input from stdin */
    data->err  = stderr;  /* default stderr to stderr */

    /* use fwrite as default function to store output */
    data->fwrite = (size_t (*)(char *, size_t, size_t, FILE *))fwrite;

    /* use fread as default function to read input */
    data->fread = (size_t (*)(char *, size_t, size_t, FILE *))fread;

    /* set the default passwd function */
    data->fpasswd = my_getpass;

    data->infilesize = -1; /* we don't know any size */

    data->current_speed = -1; /* init to negative == impossible */

    data->httpreq = HTTPREQ_GET; /* Default HTTP request */

    /* create an array with connection data struct pointers */
    data->numconnects = 5; /* hard-coded right now */
    data->connects = (struct connectdata **)
      malloc(sizeof(struct connectdata *) * data->numconnects);

    if(!data->connects) {
      free(data);
      return CURLE_OUT_OF_MEMORY;
    }

    memset(data->connects, 0, sizeof(struct connectdata *)*data->numconnects);

    *curl = data;
    return CURLE_OK;
  }

  /* this is a very serious error */
  return CURLE_OUT_OF_MEMORY;
}

CURLcode Curl_setopt(CURL *curl, CURLoption option, ...)
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
    if(data->bits.upload)
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->httpreq = HTTPREQ_PUT;
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
    if(data->bits.http_put)
      data->httpreq = HTTPREQ_PUT;
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
      data->cookies = Curl_cookie_init(cookiefile);
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
    if(data->customrequest)
      data->httpreq = HTTPREQ_CUSTOM;
    break;
  case CURLOPT_HTTPPOST:
    data->httppost = va_arg(param, struct HttpPost *);
    data->bits.http_formpost = data->httppost?1:0;
    if(data->bits.http_formpost)
      data->httpreq = HTTPREQ_POST_FORM;
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
    data->use_port = va_arg(param, long);
    break;
  case CURLOPT_POST:
    /* Does this option serve a purpose anymore? */
    data->bits.http_post = va_arg(param, long)?TRUE:FALSE;
    if(data->bits.http_post)
      data->httpreq = HTTPREQ_POST;
    break;
  case CURLOPT_POSTFIELDS:
    data->postfields = va_arg(param, char *);
    data->bits.http_post = data->postfields?TRUE:FALSE;
    if(data->bits.http_post)
      data->httpreq = HTTPREQ_POST;
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
  case CURLOPT_TELNETOPTIONS:
    data->telnet_options = va_arg(param, struct curl_slist *);
    break;
  default:
    /* unknown tag and its companion, just ignore: */
    return CURLE_READ_ERROR; /* correct this */
  }
  return CURLE_OK;
}

#if !defined(WIN32)||defined(__CYGWIN32__)
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
static
RETSIGTYPE alarmfunc(int signal)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)signal;
  return;
}
#endif

CURLcode Curl_disconnect(struct connectdata *conn)
{
  if(conn->curl_disconnect)
    /* This is set if protocol-specific cleanups should be made */
    conn->curl_disconnect(conn);

  if(conn->proto.generic)
    free(conn->proto.generic);

#ifdef ENABLE_IPV6
  if(conn->hp) /* host name info */
    freeaddrinfo(conn->hp);
#else
  if(conn->hostent_buf) /* host name info */
    free(conn->hostent_buf);
#endif

  if(conn->path) /* the URL path part */
    free(conn->path);

#ifdef USE_SSLEAY
  if (conn->ssl.use) {
    if(conn->ssl.handle) {
      (void)SSL_shutdown(conn->ssl.handle);
      SSL_set_connect_state(conn->ssl.handle);

      SSL_free (conn->ssl.handle);
      conn->ssl.handle = NULL;
    }
    if(conn->ssl.ctx) {
      SSL_CTX_free (conn->ssl.ctx);
      conn->ssl.ctx = NULL;
    }
    conn->ssl.use = FALSE; /* get back to ordinary socket usage */
  }
#endif /* USE_SSLEAY */

  /* close possibly still open sockets */
  if(-1 != conn->secondarysocket)
    sclose(conn->secondarysocket);
  if(-1 != conn->firstsocket)
    sclose(conn->firstsocket);

  if(conn->allocptr.proxyuserpwd)
    free(conn->allocptr.proxyuserpwd);
  if(conn->allocptr.uagent)
    free(conn->allocptr.uagent);
  if(conn->allocptr.userpwd)
    free(conn->allocptr.userpwd);
  if(conn->allocptr.rangeline)
    free(conn->allocptr.rangeline);
  if(conn->allocptr.ref)
    free(conn->allocptr.ref);
  if(conn->allocptr.cookie)
    free(conn->allocptr.cookie);
  if(conn->allocptr.host)
    free(conn->allocptr.host);

  if(conn->proxyhost)
    free(conn->proxyhost);

  free(conn); /* free all the connection oriented data */

  return CURLE_OK;
}

/*
 * This function should return TRUE if the socket is to be assumed to
 * be dead. Most commonly this happens when the server has closed the
 * connection due to inactivity.
 */
static bool SocketIsDead(int sock) 
{ 
  int sval; 
  bool ret_val = TRUE; 
  fd_set check_set; 
  struct timeval to; 

  FD_ZERO(&check_set); 
  FD_SET(sock,&check_set); 

  to.tv_sec = 0; 
  to.tv_usec = 1; 

  sval = select(sock + 1, &check_set, 0, 0, &to);
  if(sval == 0) 
    /* timeout */
    ret_val = FALSE; 
  
  return ret_val;
}

/*
 * Given one filled in connection struct, this function should detect if there
 * already is one that have all the significant details exactly the same and
 * thus should be used instead.
 */
static bool
ConnectionExists(struct UrlData *data,
                 struct connectdata *needle,
                 struct connectdata **usethis)
{
  size_t i;
  struct connectdata *check;

  for(i=0; i< data->numconnects; i++) {
    /*
     * Note that if we use a HTTP proxy, we check connections to that
     * proxy and not to the actual remote server.
     */
    check = data->connects[i];
    if(!check)
      /* NULL pointer means not filled-in entry */
      continue;
    if(!needle->bits.httpproxy) {
      /* The requested connection does not use a HTTP proxy */

      if(strequal(needle->protostr, check->protostr) &&
         strequal(needle->name, check->name) &&
         (needle->port == check->port) ) {
        bool dead;
        if(strequal(needle->protostr, "FTP")) {
          /* This is FTP, verify that we're using the same name and
             password as well */
          if(!strequal(needle->data->user, check->proto.ftp->user) ||
             !strequal(needle->data->passwd, check->proto.ftp->passwd)) {
            /* one of them was different */
            continue;
          }
        }
        dead = SocketIsDead(check->firstsocket);
        if(dead) {
          infof(data, "Connection %d seems to be dead!\n", i);
          Curl_disconnect(check); /* disconnect resources */
          data->connects[i]=NULL; /* nothing here */
          continue; /* try another one now */
        }
      }
      *usethis = check;
      return TRUE; /* yes, we found one to use! */
    }
    else { /* The requested needle connection is using a proxy,
              is the checked one using the same? */
      if(check->bits.httpproxy &&
         strequal(needle->proxyhost, check->proxyhost) &&
         needle->port == check->port) {
        /* This is the same proxy connection, use it! */
        *usethis = check;
        return TRUE;
      }
    }
  }
  return FALSE; /* no matching connecting exists */
}

/*
 * This function frees/closes a connection in the connection cache. This
 * should take the previously set policy into account when deciding which
 * of the connections to kill.
 */
static int
ConnectionKillOne(struct UrlData *data)
{
  size_t i;
  struct connectdata *conn;
  int highscore=-1;
  int connindex=-1;
  int score;
  CURLcode result;

  for(i=0; i< data->numconnects; i++) {
    conn = data->connects[i];
    
    if(!conn)
      continue;

    /*
     * By using the set policy, we score each connection.
     */
    switch(data->closepolicy) {
    default:
      score = 1; /* not implemented yet */
      break;
    }

    if(score > highscore) {
      highscore = score;
      connindex = i;
    }
  }
  if(connindex >= 0) {

    /* the winner gets the honour of being disconnected */
    result = Curl_disconnect(data->connects[connindex]);

    /* clean the array entry */
    data->connects[connindex] = NULL;
  }

  return connindex; /* return the available index or -1 */
}

/*
 * The given input connection struct pointer is to be stored. If the "cache"
 * is already full, we must clean out the most suitable using the previously
 * set policy.
 *
 * The given connection should be unique. That must've been checked prior to
 * this call.
 */
static unsigned int
ConnectionStore(struct UrlData *data,
                struct connectdata *conn)
{
  size_t i;
  for(i=0; i< data->numconnects; i++) {
    if(!data->connects[i])
      break;
  }
  if(i == data->numconnects) {
    /* there was no room available, kill one */
    i = ConnectionKillOne(data);
    infof(data, "Connection (#%d) was killed to make room\n", i);
  }

  data->connects[i] = conn; /* fill in this */
  conn->connectindex = i; /* make the child know where the pointer to this
                             particular data is stored */

  return i;
}

static CURLcode ConnectPlease(struct UrlData *data,
                              struct connectdata *conn)
{

#ifndef ENABLE_IPV6
  conn->firstsocket = socket(AF_INET, SOCK_STREAM, 0);

  memset((char *) &conn->serv_addr, '\0', sizeof(conn->serv_addr));
  memcpy((char *)&(conn->serv_addr.sin_addr),
         conn->hp->h_addr, conn->hp->h_length);
  conn->serv_addr.sin_family = conn->hp->h_addrtype;
  conn->serv_addr.sin_port = htons(conn->port);
#else
  /* IPv6-style */
  struct addrinfo *ai;
#endif

#if !defined(WIN32)||defined(__CYGWIN32__)
  /* We don't generally like checking for OS-versions, we should make this
     HAVE_XXXX based, although at the moment I don't have a decent test for
     this! */

#ifdef HAVE_INET_NTOA

#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif

#ifndef ENABLE_IPV6
  /*************************************************************
   * Select device to bind socket to
   *************************************************************/
  if (data->device && (strlen(data->device)<255)) {
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    char *hostdataptr=NULL;
    size_t size;
    char myhost[256] = "";
    unsigned long in;

    if(Curl_if2ip(data->device, myhost, sizeof(myhost))) {
      h = Curl_gethost(data, myhost, &hostdataptr);
    }
    else {
      if(strlen(data->device)>1) {
        h = Curl_gethost(data, data->device, &hostdataptr);
      }
      if(h) {
        /* we know data->device is shorter than the myhost array */
        strcpy(myhost, data->device);
      }
    }

    if(! *myhost) {
      /* need to fix this
         h=Curl_gethost(data,
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
	
        if( bind(conn->firstsocket, (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
          /* we succeeded to bind */
          struct sockaddr_in add;
	
          size = sizeof(add);
          if(getsockname(conn->firstsocket, (struct sockaddr *) &add,
                         (socklen_t *)&size)<0) {
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
      free(hostdataptr); /* allocated by Curl_gethost() */

  } /* end of device selection support */
#endif  /* end of HAVE_INET_NTOA */
#endif /* end of not WIN32 */
#endif /*ENABLE_IPV6*/

  /*************************************************************
   * Connect to server/proxy
   *************************************************************/
#ifdef ENABLE_IPV6
  conn->firstsocket = -1;
  for (ai = conn->hp; ai; ai = ai->ai_next) {
    conn->firstsocket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (conn->firstsocket < 0)
      continue;

    if (connect(conn->firstsocket, ai->ai_addr, ai->ai_addrlen) < 0) {
      close(conn->firstsocket);
      conn->firstsocket = -1;
      continue;
    }

    break;
  }
  conn->ai = ai;
  if (conn->firstsocket < 0) {
    failf(data, strerror(errno));
    return CURLE_COULDNT_CONNECT;
  }
#else
  if (connect(conn->firstsocket,
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
      failf(data, "Connection timed out");
      break;
    default:
      failf(data, "Can't connect to server: %d", errno);
      break;
    }
    return CURLE_COULDNT_CONNECT;
  }
#endif

  return CURLE_OK;
}

static CURLcode Connect(struct UrlData *data,
                        struct connectdata **in_connect,
                        bool allow_port) /* allow data->use_port ? */
{
  char *tmp;
  char *buf;
  CURLcode result;
  char resumerange[40]="";
  struct connectdata *conn;
  struct connectdata *conn_temp;
  char endbracket;
#ifdef HAVE_SIGACTION
  struct sigaction sigact;
#endif
  int urllen;

  /*************************************************************
   * Check input data
   *************************************************************/

  if(!data->url)
    return CURLE_URL_MALFORMAT;

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */

  conn = (struct connectdata *)malloc(sizeof(struct connectdata));
  if(!conn) {
    *in_connect = NULL; /* clear the pointer */
    return CURLE_OUT_OF_MEMORY;
  }
  /* We must set the return variable as soon as possible, so that our
     parent can cleanup any possible allocs we may have done before
     any failure */
  *in_connect = conn;

  /* we have to init the struct */
  memset(conn, 0, sizeof(struct connectdata));

  /* and we setup a few fields in case we end up actually using this struct */
  conn->data = data;           /* remember our daddy */
  conn->upload_bufsize = UPLOAD_BUFSIZE; /* default upload buffer size */
  conn->firstsocket = -1;     /* no file descriptor */
  conn->secondarysocket = -1; /* no file descriptor */
  conn->connectindex = -1;    /* no index */
  conn->bits.httpproxy = data->bits.httpproxy; /* proxy-or-not status */

  /* Default protocol-indepent behaveiour doesn't support persistant
     connections, so we set this to force-close. Protocols that support
     this need to set this to FALSE in their "curl_do" functions. */
  conn->bits.close = TRUE;


  /***********************************************************
   * We need to allocate memory to store the path in. We get the size of the
   * full URL to be sure, and we need to make it at least 256 bytes since
   * other parts of the code will rely on this fact
   ***********************************************************/
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;
  
  conn->path=(char *)malloc(urllen);
  if(NULL == conn->path)
    return CURLE_OUT_OF_MEMORY; /* really bad error */

  /*************************************************************
   * Parse the URL.
   *
   * We need to parse the url even when using the proxy, because we will need
   * the hostname and port in case we are trying to SSL connect through the
   * proxy -- and we don't know if we will need to use SSL until we parse the
   * url ...
   ************************************************************/
  if((2 == sscanf(data->url, "%64[^:]://%[^\n]",
                  conn->protostr,
                  conn->path)) && strequal(conn->protostr, "file")) {
    /*
     * we deal with file://<host>/<path> differently since it supports no
     * hostname other than "localhost" and "127.0.0.1", which is unique among
     * the URL protocols specified in RFC 1738
     */

    if (strnequal(conn->path, "localhost/", 10) ||
        strnequal(conn->path, "127.0.0.1/", 10))
      /* If there's another host name than the one we support, <host>/ is
       * quietly ommitted */
      strcpy(conn->path, &conn->path[10]);

    strcpy(conn->protostr, "file"); /* store protocol string lowercase */
  }
  else {
    /* Set default host and default path */
    strcpy(conn->gname, "curl.haxx.se");
    strcpy(conn->path, "/");

    if (2 > sscanf(data->url,
                   "%64[^\n:]://%256[^\n/]%[^\n]",
                   conn->protostr, conn->gname, conn->path)) {
      
      /*
       * The URL was badly formatted, let's try the browser-style _without_
       * protocol specified like 'http://'.
       */
      if((1 > sscanf(data->url, "%256[^\n/]%[^\n]",
                     conn->gname, conn->path)) ) {
        /*
         * We couldn't even get this format.
         */
        failf(data, "<url> malformed");
        return CURLE_URL_MALFORMAT;
      }

      /*
       * Since there was no protocol part specified, we guess what protocol it
       * is based on the first letters of the server name.
       */

      if(strnequal(conn->gname, "FTP", 3)) {
        strcpy(conn->protostr, "ftp");
      }
      else if(strnequal(conn->gname, "GOPHER", 6))
        strcpy(conn->protostr, "gopher");
#ifdef USE_SSLEAY
      else if(strnequal(conn->gname, "HTTPS", 5))
        strcpy(conn->protostr, "https");
#endif /* USE_SSLEAY */
      else if(strnequal(conn->gname, "TELNET", 6))
        strcpy(conn->protostr, "telnet");
      else if (strnequal(conn->gname, "DICT", sizeof("DICT")-1))
        strcpy(conn->protostr, "DICT");
      else if (strnequal(conn->gname, "LDAP", sizeof("LDAP")-1))
        strcpy(conn->protostr, "LDAP");
      else {
        strcpy(conn->protostr, "http");
      }

      conn->protocol |= PROT_MISSING; /* not given in URL */
    }
  }

  buf = data->buffer; /* this is our buffer */

  /*************************************************************
   * Set signal handler
   *************************************************************/
#ifdef HAVE_SIGACTION
  sigaction(SIGALRM, NULL, &sigact);
  sigact.sa_handler = alarmfunc;
#ifdef SA_RESTART
  /* HPUX doesn't have SA_RESTART but defaults to that behaviour! */
  sigact.sa_flags &= ~SA_RESTART;
#endif
  sigaction(SIGALRM, &sigact, NULL);
#else
  /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
  signal(SIGALRM, alarmfunc);
#endif

#endif

  /*************************************************************
   * Take care of user and password authentication stuff
   *************************************************************/

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

  /*************************************************************
   * Take care of proxy authentication stuff
   *************************************************************/
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

  /*************************************************************
   * Set a few convenience pointers 
   *************************************************************/
  conn->name = conn->gname;
  conn->ppath = conn->path;
  conn->hostname = conn->name;


  /*************************************************************
   * Detect what (if any) proxy to use
   *************************************************************/
  if(!data->bits.httpproxy) {
    /* If proxy was not specified, we check for default proxy environment
     * variables, to enable i.e Lynx compliance:
     *
     * http_proxy=http://some.server.dom:port/
     * https_proxy=http://some.server.dom:port/
     * ftp_proxy=http://some.server.dom:port/
     * gopher_proxy=http://some.server.dom:port/
     * no_proxy=domain1.dom,host.domain2.dom
     *   (a comma-separated list of hosts which should
     *   not be proxied, or an asterisk to override
     *   all proxy variables)
     * all_proxy=http://some.server.dom:port/
     *   (seems to exist for the CERN www lib. Probably
     *   the first to check for.)
     *
     * For compatibility, the all-uppercase versions of these variables are
     * checked if the lowercase versions don't exist.
     */
    char *no_proxy=NULL;
    char *proxy=NULL;
    char proxy_env[128];

    no_proxy=curl_getenv("no_proxy");
    if(!no_proxy)
      no_proxy=curl_getenv("NO_PROXY");

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
	char *protop = conn->protostr;
	char *envp = proxy_env;
	char *prox;

	/* Now, build <protocol>_proxy and check for such a one to use */
	while(*protop)
	  *envp++ = tolower(*protop++);

	/* append _proxy */
	strcpy(envp, "_proxy");

	/* read the protocol proxy: */
	prox=curl_getenv(proxy_env);

	if(!prox) {
          /* There was no lowercase variable, try the uppercase version: */
	  for(envp = proxy_env; *envp; envp++)
	    *envp = toupper(*envp);
	  prox=curl_getenv(proxy_env);
	}

	if(prox && *prox) { /* don't count "" strings */
	  proxy = prox; /* use this */
	}
	else {
	  proxy = curl_getenv("all_proxy"); /* default proxy to use */
	  if(!proxy)
            proxy=curl_getenv("ALL_PROXY");
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

  /*************************************************************
   * No protocol but proxy usage needs attention
   *************************************************************/
  if((conn->protocol&PROT_MISSING) && data->bits.httpproxy ) {
    /* We're guessing prefixes here and since we're told to use a proxy, we
       need to add the protocol prefix to the URL string before we continue!
       */
    char *reurl;

    reurl = aprintf("%s://%s", conn->protostr, data->url);

    if(!reurl)
      return CURLE_OUT_OF_MEMORY;

    data->url = reurl;
    if(data->freethis)
      free(data->freethis);
    data->freethis = reurl;

    conn->protocol &= ~PROT_MISSING; /* switch that one off again */
  }

  /************************************************************
   * RESUME on a HTTP page is a tricky business. First, let's just check that
   * 'range' isn't used, then set the range parameter and leave the resume as
   * it is to inform about this situation for later use. We will then
   * "attempt" to resume, and if we're talking to a HTTP/1.1 (or later)
   * server, we will get the document resumed. If we talk to a HTTP/1.0
   * server, we just fail since we can't rewind the file writing from within
   * this function.
   ***********************************************************/
  if(data->resume_from) {
    if(!data->bits.set_range) {
      /* if it already was in use, we just skip this */
      snprintf(resumerange, sizeof(resumerange), "%d-", data->resume_from);
      data->range=strdup(resumerange); /* tell ourselves to fetch this range */
      data->bits.rangestringalloc = TRUE; /* mark as allocated */
      data->bits.set_range = 1; /* switch on range usage */
    }
  }

  /*************************************************************
   * Set timeout if that is being used
   *************************************************************/
  if(data->timeout) {
    /* We set the timeout on the connection/resolving phase first, separately
     * from the download/upload part to allow a maximum time on everything */
    myalarm(data->timeout); /* this sends a signal when the timeout fires
			       off, and that will abort system calls */
  }

  /*************************************************************
   * Setup internals depending on protocol
   *************************************************************/

  if (strequal(conn->protostr, "HTTP")) {
    conn->port = (data->use_port && allow_port)?data->use_port:PORT_HTTP;
    conn->remote_port = PORT_HTTP;
    conn->protocol |= PROT_HTTP;
    conn->curl_do = Curl_http;
    conn->curl_done = Curl_http_done;
    conn->curl_close = Curl_http_close;
  }
  else if (strequal(conn->protostr, "HTTPS")) {
#ifdef USE_SSLEAY

    conn->port = (data->use_port && allow_port)?data->use_port:PORT_HTTPS;
    conn->remote_port = PORT_HTTPS;
    conn->protocol |= PROT_HTTP;
    conn->protocol |= PROT_HTTPS;

    conn->curl_do = Curl_http;
    conn->curl_done = Curl_http_done;
    conn->curl_connect = Curl_http_connect;
    conn->curl_close = Curl_http_close;

#else /* USE_SSLEAY */
    failf(data, "libcurl was built with SSL disabled, https: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
  }
  else if (strequal(conn->protostr, "GOPHER")) {
    conn->port = (data->use_port && allow_port)?data->use_port:PORT_GOPHER;
    conn->remote_port = PORT_GOPHER;
    /* Skip /<item-type>/ in path if present */
    if (isdigit((int)conn->path[1])) {
      conn->ppath = strchr(&conn->path[1], '/');
      if (conn->ppath == NULL)
	conn->ppath = conn->path;
      }
    conn->protocol |= PROT_GOPHER;
    conn->curl_do = Curl_http;
    conn->curl_done = Curl_http_done;
    conn->curl_close = Curl_http_close;
  }
  else if(strequal(conn->protostr, "FTP")) {
    char *type;
    conn->port = (data->use_port && allow_port)?data->use_port:PORT_FTP;
    conn->remote_port = PORT_FTP;
    conn->protocol |= PROT_FTP;

    if(data->bits.httpproxy &&
       !data->bits.tunnel_thru_httpproxy) {
      /* Unless we have asked to tunnel ftp operations through the proxy, we
         switch and use HTTP operations only */
      conn->curl_do = Curl_http;
      conn->curl_done = Curl_http_done;
      conn->curl_close = Curl_http_close;
    }
    else {
      conn->curl_do = Curl_ftp;
      conn->curl_done = Curl_ftp_done;
      conn->curl_connect = Curl_ftp_connect;
      conn->curl_disconnect = Curl_ftp_disconnect;
    }

    conn->ppath++; /* don't include the initial slash */

    /* FTP URLs support an extension like ";type=<typecode>" that
     * we'll try to get now! */
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
  else if(strequal(conn->protostr, "TELNET")) {
    /* telnet testing factory */
    conn->protocol |= PROT_TELNET;

    conn->port = (data->use_port && allow_port)?data->use_port: PORT_TELNET;
    conn->remote_port = PORT_TELNET;
    conn->curl_do = Curl_telnet;
    conn->curl_done = Curl_telnet_done;
  }
  else if (strequal(conn->protostr, "DICT")) {
    conn->protocol |= PROT_DICT;
    conn->port = (data->use_port && allow_port)?data->use_port:PORT_DICT;
    conn->remote_port = PORT_DICT;
    conn->curl_do = Curl_dict;
    conn->curl_done = Curl_dict_done;
  }
  else if (strequal(conn->protostr, "LDAP")) {
    conn->protocol |= PROT_LDAP;
    conn->port = (data->use_port && allow_port)?data->use_port:PORT_LDAP;
    conn->remote_port = PORT_LDAP;
    conn->curl_do = Curl_ldap;
    conn->curl_done = Curl_ldap_done;
  }
  else if (strequal(conn->protostr, "FILE")) {
    conn->protocol |= PROT_FILE;

    conn->curl_do = Curl_file;
    /* no done() function */

    /* anyway, this is supposed to be the connect function so we better
       at least check that the file is present here! */
    result = Curl_file_connect(conn);

    /* Setup a "faked" transfer that'll do nothing */
    if(CURLE_OK == result) {
      result = Curl_Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                             -1, NULL); /* no upload */
    }

    return result;
  }
  else {
    /* We fell through all checks and thus we don't support the specified
       protocol */
    failf(data, "Unsupported protocol: %s", conn->protostr);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  /*************************************************************
   * .netrc scanning coming up
   *************************************************************/
  if(data->bits.use_netrc) {
    if(Curl_parsenetrc(conn->hostname, data->user, data->passwd)) {
      infof(data, "Couldn't find host %s in the .netrc file, using defaults",
            conn->hostname);
    }
    else
      data->bits.user_passwd = 1; /* enable user+password */

    /* weather we failed or not, we don't know which fields that were filled
       in anyway */
    if(!data->user[0])
      strcpy(data->user, CURL_DEFAULT_USER);
    if(!data->passwd[0])
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
  }
  else if(!(data->bits.user_passwd) &&
	  (conn->protocol & (PROT_FTP|PROT_HTTP)) ) {
    /* This is a FTP or HTTP URL, and we haven't got the user+password in
     * the extra parameter, we will now try to extract the possible
     * user+password pair in a string like:
     * ftp://user:password@ftp.my.site:8021/README */
    char *ptr=NULL; /* assign to remove possible warnings */
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

  /*************************************************************
   * Figure out the remote port number
   *
   * No matter if we use a proxy or not, we have to figure out the remote
   * port number of various reasons.
   *
   * To be able to detect port number flawlessly, we must not confuse them
   * IPv6-specified addresses in the [0::1] style.
   *************************************************************/

  if((1 == sscanf(conn->name, "[%*39[0-9a-fA-F:]%c", &endbracket)) &&
     (']' == endbracket)) {
    /* this is a IPv6-style specified IP-address */
#ifndef ENABLE_IPV6
    failf(data, "You haven't enabled IPv6 support");
    return CURLE_URL_MALFORMAT;
#else
    tmp = strchr(conn->name, ']');

    tmp++; /* pass the ending bracket */
    if(':' != *tmp)
      tmp = NULL; /* no port number available */
#endif
  }
  else {
    /* traditional IPv4-style port-extracting */
    tmp = strchr(conn->name, ':');
  }

  if (tmp) {
    *tmp++ = '\0'; /* cut off the name there */
    conn->remote_port = atoi(tmp);
  }

  if(data->bits.httpproxy) {
    /* If this is supposed to use a proxy, we need to figure out the proxy
       host name name, so that we can re-use an existing connection
       that may exist registered to the same proxy host. */

#ifdef ENABLE_IPV6
    failf(data, "proxy yet to be supported");
    return CURLE_OUT_OF_MEMORY;
#else
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
      conn->port = atoi(prox_portno);
    }
    else if(data->proxyport) {
      /* None given in the proxy string, then get the default one if it is
         given */
      conn->port = data->proxyport;
    }

    /* now, clone the cleaned proxy host name */
    conn->proxyhost = strdup(proxyptr);

    free(proxydup); /* free the duplicate pointer and not the modified */
#endif /* end of IPv4-section */
  }

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  if(ConnectionExists(data, conn, &conn_temp)) {
    /*
     * We already have a connection for this, we got the former connection
     * in the conn_temp variable and thus we need to cleanup the one we
     * just allocated before we can move along and use the previously
     * existing one.
     */
    struct connectdata *old_conn = conn;
    char *path = old_conn->path; /* setup the current path pointer properly */
    if(old_conn->proxyhost)
      free(old_conn->proxyhost);
    conn = conn_temp;        /* use this connection from now on */
    free(conn->path);        /* free the previous path pointer */

    /* we need these pointers if we speak over a proxy */
    conn->name = old_conn->name;
    conn->hostname = old_conn->hostname;

    conn->path = path;       /* use this one */
    conn->ppath = path;      /* set this too */

    /* re-use init */
    conn->maxdownload = 0;   /* might have been used previously! */
    conn->bits.reuse = TRUE; /* yes, we're re-using here */

    free(old_conn);          /* we don't need this anymore */

    *in_connect = conn;      /* return this instead! */

    infof(data, "Re-using existing connection! (#%d)\n", conn->connectindex);
  }
  else {
    /*
     * This is a brand new connection, so let's store it in the connection
     * cache of ours!
     */
    ConnectionStore(data, conn);
  }

  /*************************************************************
   * Resolve the name of the server or proxy
   *************************************************************/
  if(!data->bits.httpproxy) {
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    conn->port =  conn->remote_port; /* it is the same port */

    /* Resolve target host right on */
    if(!conn->hp) {
#ifdef ENABLE_IPV6
      /* it might already be set if reusing a connection */
      conn->hp = Curl_getaddrinfo(data, conn->name, conn->port);
#else
      /* it might already be set if reusing a connection */
      conn->hp = Curl_gethost(data, conn->name, &conn->hostent_buf);
#endif
    }
    if(!conn->hp)
    {
      failf(data, "Couldn't resolve host '%s'", conn->name);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }
  else if(!conn->hp) {
    /* This is a proxy that hasn't been resolved yet. It may be resolved
       if we're reusing an existing connection. */

    /* resolve proxy */
    conn->hp = Curl_gethost(data, conn->proxyhost, &conn->hostent_buf);
    if(!conn->hp) {
      failf(data, "Couldn't resolve proxy '%s'", conn->proxyhost);
      return CURLE_COULDNT_RESOLVE_PROXY;
    }
  }
  Curl_pgrsTime(data, TIMER_NAMELOOKUP);

  /*************************************************************
   * Proxy authentication
   *************************************************************/
  if(data->bits.proxy_user_passwd) {
    char *authorization;
    snprintf(data->buffer, BUFSIZE, "%s:%s",
             data->proxyuser, data->proxypasswd);
    if(Curl_base64_encode(data->buffer, strlen(data->buffer),
                          &authorization) >= 0) {
      if(conn->allocptr.proxyuserpwd)
        free(conn->allocptr.proxyuserpwd);
      conn->allocptr.proxyuserpwd =
        aprintf("Proxy-authorization: Basic %s\015\012", authorization);
      free(authorization);
    }
  }

  /*************************************************************
   * Send user-agent to HTTP proxies even if the target protocol
   * isn't HTTP.
   *************************************************************/
  if((conn->protocol&PROT_HTTP) || data->bits.httpproxy) {
    if(data->useragent) {
      if(conn->allocptr.uagent)
        free(conn->allocptr.uagent);
      conn->allocptr.uagent =
        aprintf("User-Agent: %s\015\012", data->useragent);
    }
  }

  if(-1 == conn->firstsocket) {
    /* Connect only if not already connected! */
    result = ConnectPlease(data, conn);
    if(CURLE_OK != result)
      return result;

    if(conn->curl_connect) {
      /* is there a connect() procedure? */

      /* set start time here for timeout purposes in the
       * connect procedure, it is later set again for the
       * progress meter purpose */
      conn->now = Curl_tvnow();

      /* Call the protocol-specific connect function */
      result = conn->curl_connect(conn);
      if(result != CURLE_OK)
        return result; /* pass back errors */
    }
  }

  Curl_pgrsTime(data, TIMER_CONNECT); /* we're connected */

  conn->now = Curl_tvnow(); /* time this *after* the connect is done */
  conn->bytecount = 0;
  
  /* Figure out the ip-number and display the first host name it shows: */
#ifdef ENABLE_IPV6
  {
    char hbuf[NI_MAXHOST];
#ifdef NI_WITHSCOPEID
    const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
    const int niflags = NI_NUMERICHOST;
#endif
    struct addrinfo *ai = conn->ai;

    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf), NULL, 0,
	niflags)) {
      snprintf(hbuf, sizeof(hbuf), "?");
    }
    if (ai->ai_canonname) {
      infof(data, "Connected to %s (%s)\n", ai->ai_canonname, hbuf);
    } else {
      infof(data, "Connected to %s\n", hbuf);
    }
  }
#else
  {
    struct in_addr in;
    (void) memcpy(&in.s_addr, *conn->hp->h_addr_list, sizeof (in.s_addr));
    infof(data, "Connected to %s (%s)\n", conn->hp->h_name, inet_ntoa(in));
  }
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

CURLcode Curl_connect(struct UrlData *data,
                      struct connectdata **in_connect,
                      bool allow_port)
{
  CURLcode code;
  struct connectdata *conn;

  /* call the stuff that needs to be called */
  code = Connect(data, in_connect, allow_port);

  if(CURLE_OK != code) {
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    conn = (struct connectdata *)*in_connect;
    if(conn) {
      int index;
      index = conn->connectindex; /* get the index */
      Curl_disconnect(conn);      /* close the connection */
      if(-1 != index)
        data->connects[index]=NULL; /* clear the pointer */
    }
  }
  return code;
}


CURLcode Curl_done(struct connectdata *conn)
{
  struct UrlData *data;
  CURLcode result;
  int index;

  data = conn->data;

  /* this calls the protocol-specific function pointer previously set */
  if(conn->curl_done)
    result = conn->curl_done(conn);
  else
    result = CURLE_OK;

  Curl_pgrsDone(data); /* done with the operation */

  /* if bits.close is TRUE, it means that the connection should be closed
     in spite of all our efforts to be nice */
  if((CURLE_OK == result) && conn->bits.close) {
    index = conn->connectindex;     /* get the index */
    result = Curl_disconnect(conn); /* close the connection */
    data->connects[index]=NULL;     /* clear the pointer */
  }

  return result;
}

CURLcode Curl_do(struct connectdata *conn)
{
  CURLcode result=CURLE_OK;

  if(conn->curl_do)
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->curl_do(conn);

  return result;
}

