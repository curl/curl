/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef	VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
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
#include "strtok.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "http.h"
#include "file.h"
#include "ldap.h"
#include "url.h"
#include "connect.h"
#include "ca-bundle.h"

#include <curl/types.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

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
static int ConnectionKillOne(struct SessionHandle *data);
static bool ConnectionExists(struct SessionHandle *data,
                             struct connectdata *needle,
                             struct connectdata **usethis);
static unsigned int ConnectionStore(struct SessionHandle *data,
                                    struct connectdata *conn);


#if !defined(WIN32)||defined(__CYGWIN32__)
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
#ifdef HAVE_SIGSETJMP
extern sigjmp_buf curl_jmpenv;
#endif
static
RETSIGTYPE alarmfunc(int signal)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)signal;
#ifdef HAVE_SIGSETJMP
  siglongjmp(curl_jmpenv, 1);
#endif
  return;
}
#endif


/*
 * This is the internal function curl_easy_cleanup() calls. This should
 * cleanup and free all resources associated with this sessionhandle.
 *
 * NOTE: if we ever add something that attempts to write to a socket or
 * similar here, we must ignore SIGPIPE first. It is currently only done
 * when curl_easy_perform() is invoked.
 */

CURLcode Curl_close(struct SessionHandle *data)
{
  /* Loop through all open connections and kill them one by one */
  while(-1 != ConnectionKillOne(data));

#ifdef USE_SSLEAY
  /* Close down all open SSL info and sessions */
  Curl_SSL_Close_All(data);
#endif

  /* No longer a dirty share, if it exists */
  if (data->share)
    data->share->dirty--;

  if(data->change.cookielist) /* clean up list if any */
    curl_slist_free_all(data->change.cookielist);

  if(data->state.auth_host)
    free(data->state.auth_host);

  if(data->change.proxy_alloc)
    free(data->change.proxy);

  if(data->change.referer_alloc)
    free(data->change.referer);

  if(data->change.url_alloc)
    free(data->change.url);

  if(data->state.headerbuff)
    free(data->state.headerbuff);

#ifndef CURL_DISABLE_HTTP
  if(data->set.cookiejar)
    /* we have a "destination" for all the cookies to get dumped to */
    Curl_cookie_output(data->cookies, data->set.cookiejar);
    
  Curl_cookie_cleanup(data->cookies);
#endif

  /* free the connection cache */
  free(data->state.connects);

  if(data->info.contenttype)
    free(data->info.contenttype);

  free(data);
  return CURLE_OK;
}

static
int my_getpass(void *clientp, const char *prompt, char* buffer, int buflen )
{
  char *retbuf;
  clientp=NULL; /* prevent compiler warning */

  retbuf = getpass_r(prompt, buffer, buflen);
  if(NULL == retbuf)
    return 1;
  else
    return 0; /* success */
}


CURLcode Curl_open(struct SessionHandle **curl)
{
  /* We don't yet support specifying the URL at this point */
  struct SessionHandle *data;
  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = (struct SessionHandle *)malloc(sizeof(struct SessionHandle));
  if(!data)
    /* this is a very serious error */
    return CURLE_OUT_OF_MEMORY;
  
  memset(data, 0, sizeof(struct SessionHandle));

  /* We do some initial setup here, all those fields that can't be just 0 */

  data->state.headerbuff=(char*)malloc(HEADERSIZE);
  if(!data->state.headerbuff) {
    free(data); /* free the memory again */
    return CURLE_OUT_OF_MEMORY;
  }

  data->state.headersize=HEADERSIZE;

  data->set.out = stdout; /* default output to stdout */
  data->set.in  = stdin;  /* default input from stdin */
  data->set.err  = stderr;  /* default stderr to stderr */
  
  /* use fwrite as default function to store output */
  data->set.fwrite = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  data->set.fread = (curl_read_callback)fread;
  
  /* set the default passwd function */
  data->set.fpasswd = my_getpass;

  data->set.infilesize = -1; /* we don't know any size */

  data->state.current_speed = -1; /* init to negative == impossible */

  data->set.httpreq = HTTPREQ_GET; /* Default HTTP request */
  data->set.ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */

  data->set.dns_cache_timeout = 60; /* Timeout every 60 seconds by default */
  
  /* make libcurl quiet by default: */
  data->set.hide_progress = TRUE;  /* CURLOPT_NOPROGRESS changes these */
  data->progress.flags |= PGRS_HIDE;

  /* Set the default size of the SSL session ID cache */
  data->set.ssl.numsessions = 5;

  data->set.proxyport = 1080;
  
  data->set.proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */

  /* create an array with connection data struct pointers */
  data->state.numconnects = 5; /* hard-coded right now */
  data->state.connects = (struct connectdata **)
    malloc(sizeof(struct connectdata *) * data->state.numconnects);
  
  if(!data->state.connects) {
    free(data);
    return CURLE_OUT_OF_MEMORY;
  }

  /*
   * libcurl 7.10 introduces SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  data->set.ssl.verifypeer = TRUE;
  data->set.ssl.verifyhost = 2;
#ifdef CURL_CA_BUNDLE
  /* This is our prefered CA cert bundle since install time */
  data->set.ssl.CAfile = (char *)CURL_CA_BUNDLE;
#endif


  memset(data->state.connects, 0,
         sizeof(struct connectdata *)*data->state.numconnects);

  *curl = data;
  return CURLE_OK;
}

CURLcode Curl_setopt(struct SessionHandle *data, CURLoption option, ...)
{
  va_list param;
  char *cookiefile;

  va_start(param, option);

  switch(option) {
  case CURLOPT_DNS_CACHE_TIMEOUT:
    data->set.dns_cache_timeout = va_arg(param, int);
    break;
  case CURLOPT_DNS_USE_GLOBAL_CACHE: 
    {
      int use_cache = va_arg(param, int);
      if (use_cache) {
        Curl_global_host_cache_init();
      }

      data->set.global_dns_cache = use_cache;
    }
    break;
  case CURLOPT_SSL_CIPHER_LIST:
    /* set a list of cipher we want to use in the SSL connection */
    data->set.ssl.cipher_list = va_arg(param, char *);
    break;

  case CURLOPT_RANDOM_FILE:
    /*
     * This is the path name to a file that contains random data to seed
     * the random SSL stuff with. The file is only used for reading.
     */
    data->set.ssl.random_file = va_arg(param, char *);
    break;
  case CURLOPT_EGDSOCKET:
    /*
     * The Entropy Gathering Daemon socket pathname
     */
    data->set.ssl.egdsocket = va_arg(param, char *);
    break;
  case CURLOPT_MAXCONNECTS:
    /*
     * Set the absolute number of maximum simultaneous alive connection that
     * libcurl is allowed to have.
     */
    {
      long newconnects= va_arg(param, long);
      struct connectdata **newptr;

      if(newconnects < data->state.numconnects) {
        /* Since this number is *decreased* from the existing number, we must
           close the possibly open connections that live on the indexes that
           are being removed! */
        int i;
        for(i=newconnects; i< data->state.numconnects; i++)
          Curl_disconnect(data->state.connects[i]);
      }
      if(newconnects) {
        newptr= (struct connectdata **)
          realloc(data->state.connects,
                  sizeof(struct connectdata *) * newconnects);
        if(!newptr)
          /* we closed a few connections in vain, but so what? */
          return CURLE_OUT_OF_MEMORY;
        data->state.connects = newptr;
        data->state.numconnects = newconnects;
      }
      else {
        /* zero makes NO cache at all */
        if(data->state.connects)
          free(data->state.connects);
        data->state.connects=NULL;
        data->state.numconnects=0;
      }
    }
    break;
  case CURLOPT_FORBID_REUSE:
    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    data->set.reuse_forbid = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FRESH_CONNECT:
    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    data->set.reuse_fresh = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_VERBOSE:
    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    data->set.verbose = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_HEADER:
    /*
     * Set to include the header in the general data output stream.
     */
    data->set.http_include_header = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_NOPROGRESS:
    /*
     * Shut off the internal supported progress meter
     */
    data->set.hide_progress = va_arg(param, long)?TRUE:FALSE;
    if(data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else
      data->progress.flags &= ~PGRS_HIDE;
    break;
  case CURLOPT_NOBODY:
    /*
     * Do not include the body part in the output data stream.
     */
    data->set.no_body = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FAILONERROR:
    /*
     * Don't output the >=300 error code HTML-page, but instead only
     * return error.
     */
    data->set.http_fail_on_error = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_UPLOAD:
    /*
     * We want to sent data to the remote host
     */
    data->set.upload = va_arg(param, long)?TRUE:FALSE;
    if(data->set.upload)
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->set.httpreq = HTTPREQ_PUT;
    break;
  case CURLOPT_FILETIME:
    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using curl_easy_getinfo().
     */
    data->set.get_filetime = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FTPLISTONLY:
    /*
     * An FTP option that changes the command to one that asks for a list
     * only, no file info details.
     */
    data->set.ftp_list_only = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_FTPAPPEND:
    /*
     * We want to upload and append to an existing (FTP) file.
     */
    data->set.ftp_append = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_NETRC:
    /*
     * Parse the $HOME/.netrc file
     */
    data->set.use_netrc = va_arg(param, long);
    break;
  case CURLOPT_FOLLOWLOCATION:
    /*
     * Follow Location: header hints on a HTTP-server.
     */
    data->set.http_follow_location = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_HTTP_VERSION:
    /*
     * This sets a requested HTTP version to be used. The value is one of
     * the listed enums in curl/curl.h.
     */
    data->set.httpversion = va_arg(param, long);
    break;
  case CURLOPT_TRANSFERTEXT:
    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    data->set.ftp_ascii = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_PUT:
    /*
     * Use the HTTP PUT request to transfer data if this is TRUE.  If this is
     * FALSE, don't set the httpreq. We can't know what to revert it to!
     */
    if(va_arg(param, long))
      data->set.httpreq = HTTPREQ_PUT;
    break;
  case CURLOPT_TIMECONDITION:
    /*
     * Set HTTP time condition. This must be one of the defines in the
     * curl/curl.h header file.
     */
    data->set.timecondition = va_arg(param, long);
    break;
  case CURLOPT_TIMEVALUE:
    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    data->set.timevalue = va_arg(param, long);
    break;
  case CURLOPT_SSLVERSION:
    /*
     * Set explicit SSL version to try to connect with, as some SSL
     * implementations are lame.
     */
    data->set.ssl.version = va_arg(param, long);
    break;

  case CURLOPT_COOKIESESSION:
    /*
     * Set this option to TRUE to start a new "cookie session". It will
     * prevent the forthcoming read-cookies-from-file actions to accept
     * cookies that are marked as being session cookies, as they belong to a
     * previous session.
     *
     * In the original Netscape cookie spec, "session cookies" are cookies
     * with no expire date set. RFC2109 describes the same action if no
     * 'Max-Age' is set and RFC2965 includes the RFC2109 description and adds
     * a 'Discard' action that can enforce the discard even for cookies that
     * have a Max-Age.
     *
     * We run mostly with the original cookie spec, as hardly anyone implements
     * anything else.
     */
    data->set.cookiesession = (bool)va_arg(param, long);
    break;

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_COOKIEFILE:
    /*
     * Set cookie file to read and parse. Can be used multiple times.
     */
    cookiefile = (char *)va_arg(param, void *);
    if(cookiefile)
      /* append the cookie file name to the list of file names, and deal with
         them later */
      data->change.cookielist =
        curl_slist_append(data->change.cookielist, cookiefile);
    break;

  case CURLOPT_COOKIEJAR:
    /*
     * Set cookie file name to dump all cookies to when we're done.
     */
    data->set.cookiejar = (char *)va_arg(param, void *);

    /*
     * Activate the cookie parser. This may or may not already
     * have been made.
     */
    data->cookies = Curl_cookie_init(NULL, data->cookies,
                                     data->set.cookiesession);
    break;
#endif

  case CURLOPT_WRITEHEADER:
    /*
     * Custom pointer to pass the header write callback function
     */
    data->set.writeheader = (void *)va_arg(param, void *);
    break;
  case CURLOPT_COOKIE:
    /*
     * Cookie string to send to the remote server in the request.
     */
    data->set.cookie = va_arg(param, char *);
    break;
  case CURLOPT_ERRORBUFFER:
    /*
     * Error buffer provided by the caller to get the human readable
     * error string in.
     */
    data->set.errorbuffer = va_arg(param, char *);
    break;
  case CURLOPT_FILE:
    /*
     * FILE pointer to write to or include in the data write callback
     */
    data->set.out = va_arg(param, FILE *);
    break;
  case CURLOPT_FTPPORT:
    /*
     * Use FTP PORT, this also specifies which IP address to use
     */
    data->set.ftpport = va_arg(param, char *);
    data->set.ftp_use_port = data->set.ftpport?1:0;
    break;

  case CURLOPT_FTP_USE_EPSV:
    data->set.ftp_use_epsv = va_arg(param, long)?TRUE:FALSE;
    break;

  case CURLOPT_HTTPHEADER:
    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    data->set.headers = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_CUSTOMREQUEST:
    /*
     * Set a custom string to use as request
     */
    data->set.customrequest = va_arg(param, char *);

    /* we don't set
       data->set.httpreq = HTTPREQ_CUSTOM;
       here, we continue as if we were using the already set type
       and this just changes the actual request keyword */
    break;
  case CURLOPT_HTTPPOST:
    /*
     * Set to make us do HTTP POST
     */
    data->set.httppost = va_arg(param, struct HttpPost *);
    if(data->set.httppost)
      data->set.httpreq = HTTPREQ_POST_FORM;
    break;

  case CURLOPT_HTTPGET:
    /*
     * Set to force us do HTTP GET
     */
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_GET;
      data->set.upload = FALSE; /* switch off upload */
    }
    break;

  case CURLOPT_INFILE:
    /*
     * FILE pointer to read the file to be uploaded from. Or possibly
     * used as argument to the read callback.
     */
    data->set.in = va_arg(param, FILE *);
    break;
  case CURLOPT_INFILESIZE:
    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    data->set.infilesize = va_arg(param, long);
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    /*
     * The low speed limit that if transfers are below this for
     * CURLOPT_LOW_SPEED_TIME, the transfer is aborted.
     */
    data->set.low_speed_limit=va_arg(param, long);
    break;
  case CURLOPT_LOW_SPEED_TIME:
    /*
     * The low speed time that if transfers are below the set
     * CURLOPT_LOW_SPEED_LIMIT during this time, the transfer is aborted.
     */
    data->set.low_speed_time=va_arg(param, long);
    break;
  case CURLOPT_URL:
    /*
     * The URL to fetch.
     */
    if(data->change.url_alloc) {
      /* the already set URL is allocated, free it first! */
      free(data->change.url);
      data->change.url_alloc=FALSE;
    }
    data->set.set_url = va_arg(param, char *);
    data->change.url = data->set.set_url;
    break;
  case CURLOPT_PORT:
    /*
     * The port number to use when getting the URL
     */
    data->set.use_port = va_arg(param, long);
    break;
  case CURLOPT_POST:
    /* Does this option serve a purpose anymore? Yes it does, when
       CURLOPT_POSTFIELDS isn't used and the POST data is read off the
       callback! */
    if(va_arg(param, long))
      data->set.httpreq = HTTPREQ_POST;
    break;
  case CURLOPT_POSTFIELDS:
    /*
     * A string with POST data. Makes curl HTTP POST.
     */
    data->set.postfields = va_arg(param, char *);
    if(data->set.postfields)
      data->set.httpreq = HTTPREQ_POST;
    break;
  case CURLOPT_POSTFIELDSIZE:
    /*
     * The size of the POSTFIELD data, if curl should now do a strlen
     * to find out. Enables binary posts.
     */
    data->set.postfieldsize = va_arg(param, long);
    break;
  case CURLOPT_REFERER:
    /*
     * String to set in the HTTP Referer: field.
     */
    if(data->change.referer_alloc) {
      free(data->change.referer);
      data->change.referer_alloc = FALSE;
    }
    data->set.set_referer = va_arg(param, char *);
    data->change.referer = data->set.set_referer;
    break;
  case CURLOPT_AUTOREFERER:
    /*
     * Switch on automatic referer that gets set if curl follows locations.
     */
    data->set.http_auto_referer = va_arg(param, long)?1:0;
    break;
  case CURLOPT_PROXY:
    /*
     * Set proxy server:port to use as HTTP proxy.
     *
     * If the proxy is set to "" we explicitly say that we don't want to use a
     * proxy (even though there might be environment variables saying so).
     *
     * Setting it to NULL, means no proxy but allows the environment variables
     * to decide for us.
     */
    if(data->change.proxy_alloc) {
      /*
       * The already set string is allocated, free that first
       */
      data->change.proxy_alloc=FALSE;;
      free(data->change.proxy);
    }
    data->set.set_proxy = va_arg(param, char *);
    data->change.proxy = data->set.set_proxy;
    break;
  case CURLOPT_HTTPPROXYTUNNEL:
    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    data->set.tunnel_thru_httpproxy = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_PROXYPORT:
    /*
     * Explicitly set HTTP proxy port number.
     */
    data->set.proxyport = va_arg(param, long);
    break;
  case CURLOPT_TIMEOUT:
    /*
     * The maximum time you allow curl to use for a single transfer
     * operation.
     */
    data->set.timeout = va_arg(param, long);
    break;
  case CURLOPT_CONNECTTIMEOUT:
    /*
     * The maximum time you allow curl to use to connect.
     */
    data->set.connecttimeout = va_arg(param, long);
    break;
  case CURLOPT_MAXREDIRS:
    /*
     * The maximum amount of hops you allow curl to follow Location:
     * headers. This should mostly be used to detect never-ending loops.
     */
    data->set.maxredirs = va_arg(param, long);
    break;
  case CURLOPT_USERAGENT:
    /*
     * String to use in the HTTP User-Agent field
     */
    data->set.useragent = va_arg(param, char *);
    break;
  case CURLOPT_ENCODING:
    /*
     * String to use at the value of Accept-Encoding header. 08/28/02 jhrg
     */
    data->set.encoding = va_arg(param, char *);
    break;

  case CURLOPT_USERPWD:
    /*
     * user:password to use in the operation
     */
    data->set.userpwd = va_arg(param, char *);
    break;
  case CURLOPT_POSTQUOTE:
    /*
     * List of RAW FTP commands to use after a transfer 
     */
    data->set.postquote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_PREQUOTE:
    /*
     * List of RAW FTP commands to use prior to RETR (Wesley Laxton)
     */
    data->set.prequote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_QUOTE:
    /*
     * List of RAW FTP commands to use before a transfer 
     */
    data->set.quote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_PROGRESSFUNCTION:
    /*
     * Progress callback function
     */
    data->set.fprogress = va_arg(param, curl_progress_callback);
    if(data->set.fprogress)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */

    break;
  case CURLOPT_PROGRESSDATA:
    /*
     * Custom client data to pass to the progress callback
     */
    data->set.progress_client = va_arg(param, void *);
    break;
  case CURLOPT_PASSWDFUNCTION:
    /*
     * Password prompt callback
     */
    data->set.fpasswd = va_arg(param, curl_passwd_callback);
    /*
     * if the callback provided is null, reset the default callback
     */
    if(!data->set.fpasswd)
    {
      data->set.fpasswd = my_getpass;
    }
    break;
  case CURLOPT_PASSWDDATA:
    /*
     * Custom client data to pass to the password callback
     */
    data->set.passwd_client = va_arg(param, void *);
    break;
  case CURLOPT_PROXYUSERPWD:
    /*
     * user:password needed to use the proxy
     */
    data->set.proxyuserpwd = va_arg(param, char *);
    break;
  case CURLOPT_RANGE:
    /*
     * What range of the file you want to transfer
     */
    data->set.set_range = va_arg(param, char *);
    break;
  case CURLOPT_RESUME_FROM:
    /*
     * Resume transfer at the give file position
     */
    data->set.set_resume_from = va_arg(param, long);
    break;
  case CURLOPT_DEBUGFUNCTION:
    /*
     * stderr write callback.
     */
    data->set.fdebug = va_arg(param, curl_debug_callback);
    /*
     * if the callback provided is NULL, it'll use the default callback
     */
    break;
  case CURLOPT_DEBUGDATA:
    /*
     * Set to a void * that should receive all error writes. This
     * defaults to CURLOPT_STDERR for normal operations.
     */
    data->set.debugdata = va_arg(param, void *);
    break;
  case CURLOPT_STDERR:
    /*
     * Set to a FILE * that should receive all error writes. This
     * defaults to stderr for normal operations.
     */
    data->set.err = va_arg(param, FILE *);
    if(!data->set.err)
      data->set.err = stderr;
    break;
  case CURLOPT_HEADERFUNCTION:
    /*
     * Set header write callback
     */
    data->set.fwrite_header = va_arg(param, curl_write_callback);
    break;
  case CURLOPT_WRITEFUNCTION:
    /*
     * Set data write callback
     */
    data->set.fwrite = va_arg(param, curl_write_callback);
    break;
  case CURLOPT_READFUNCTION:
    /*
     * Read data callback
     */
    data->set.fread = va_arg(param, curl_read_callback);
    break;
  case CURLOPT_SSLCERT:
    /*
     * String that holds file name of the SSL certificate to use
     */
    data->set.cert = va_arg(param, char *);
    break;
  case CURLOPT_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use
     */
    data->set.cert_type = va_arg(param, char *);
    break;
  case CURLOPT_SSLKEY:
    /*
     * String that holds file name of the SSL certificate to use
     */
    data->set.key = va_arg(param, char *);
    break;
  case CURLOPT_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL certificate to use
     */
    data->set.key_type = va_arg(param, char *);
    break;
  case CURLOPT_SSLKEYPASSWD:
    /*
     * String that holds the SSL private key password.
     */
    data->set.key_passwd = va_arg(param, char *);
    break;
  case CURLOPT_SSLENGINE:
    /*
     * String that holds the SSL crypto engine.
     */
#ifdef HAVE_OPENSSL_ENGINE_H
    {
      const char *cpTemp = va_arg(param, char *);
      ENGINE     *e;
      if (cpTemp && cpTemp[0]) {
        e = ENGINE_by_id(cpTemp);
        if (e) {
          if (data->engine) {
            ENGINE_free(data->engine);
          }
          data->engine = e;
        }
        else {
          failf(data, "SSL Engine '%s' not found", cpTemp);
          return CURLE_SSL_ENGINE_NOTFOUND;
        }
      }
    }
#else
    return CURLE_SSL_ENGINE_NOTFOUND;
#endif
    break;
  case CURLOPT_SSLENGINE_DEFAULT:
    /*
     * flag to set engine as default.
     */
#ifdef HAVE_OPENSSL_ENGINE_H
    if (data->engine) {
      if (ENGINE_set_default(data->engine, ENGINE_METHOD_ALL) > 0) {
#ifdef DEBUG
        fprintf(stderr,"set default crypto engine\n");
#endif
      }
      else {
#ifdef DEBUG
        failf(data, "set default crypto engine failed");
#endif
        return CURLE_SSL_ENGINE_SETFAILED;
      }
    }
#endif
    break;
  case CURLOPT_CRLF:
    /*
     * Kludgy option to enable CRLF convertions. Subject for removal.
     */
    data->set.crlf = va_arg(param, long)?TRUE:FALSE;
    break;
  case CURLOPT_INTERFACE:
    /*
     * Set what interface to bind to when performing an operation and thus
     * what from-IP your connection will use.
     */
    data->set.device = va_arg(param, char *);
    break;
  case CURLOPT_KRB4LEVEL:
    /*
     * A string that defines the krb4 security level.
     */
    data->set.krb4_level = va_arg(param, char *);
    data->set.krb4=data->set.krb4_level?TRUE:FALSE;
    break;
  case CURLOPT_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying.
     */
    data->set.ssl.verifypeer = va_arg(param, long);
    break;
  case CURLOPT_SSL_VERIFYHOST:
    /*
     * Enable verification of the CN contained in the peer certificate
     */
    data->set.ssl.verifyhost = va_arg(param, long);
    break;
  case CURLOPT_CAINFO:
    /*
     * Set CA info for SSL connection. Specify file name of the CA certificate
     */
    data->set.ssl.CAfile = va_arg(param, char *);
    break;
  case CURLOPT_CAPATH:
    /*
     * Set CA path info for SSL connection. Specify directory name of the CA
     * certificates which have been prepared using openssl c_rehash utility.
     */
    /* This does not work on windows. */
    data->set.ssl.CApath = va_arg(param, char *);
    break;
  case CURLOPT_TELNETOPTIONS:
    /*
     * Set a linked list of telnet options
     */
    data->set.telnet_options = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_BUFFERSIZE:
    /*
     * The application kindly asks for a differently sized receive buffer.
     * If it seems reasonable, we'll use it.
     */
    data->set.buffer_size = va_arg(param, long);

    if(data->set.buffer_size> (BUFSIZE -1 ))
      data->set.buffer_size = 0; /* huge internal default */

    break;

  case CURLOPT_NOSIGNAL:
    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    data->set.no_signal = va_arg(param, long) ? TRUE : FALSE;
    break;

  case CURLOPT_SHARE:
    {
      curl_share *set;
      set = va_arg(param, curl_share *);
      if(data->share)
        data->share->dirty--;

      data->share = set;
      data->share->dirty++;
    }
    break;

  case CURLOPT_PROXYTYPE:
    /*
     * Set proxy type. HTTP/SOCKS4/SOCKS5
     */
    data->set.proxytype = va_arg(param, long);
    break;

  default:
    /* unknown tag and its companion, just ignore: */
    return CURLE_FAILED_INIT; /* correct this */
  }
  return CURLE_OK;
}

CURLcode Curl_disconnect(struct connectdata *conn)
{
  if(!conn)
    return CURLE_OK; /* this is closed and fine already */

  /*
   * The range string is usually freed in curl_done(), but we might
   * get here *instead* if we fail prematurely. Thus we need to be able
   * to free this resource here as well.
   */
  if(conn->bits.rangestringalloc) {
    free(conn->range);
    conn->bits.rangestringalloc = FALSE;
  }

  if(-1 != conn->connectindex) {
    /* unlink ourselves! */
    infof(conn->data, "Closing connection #%d\n", conn->connectindex);
    conn->data->state.connects[conn->connectindex] = NULL;
  }

  if(conn->curl_disconnect)
    /* This is set if protocol-specific cleanups should be made */
    conn->curl_disconnect(conn);

  if(conn->proto.generic)
    free(conn->proto.generic);

  if(conn->newurl)
    free(conn->newurl);

  if(conn->path) /* the URL path part */
    free(conn->path);

#ifdef USE_SSLEAY
  Curl_SSL_Close(conn);
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
  if(conn->allocptr.accept_encoding)
    free(conn->allocptr.accept_encoding);
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
  to.tv_usec = 0; 

  sval = select(sock + 1, &check_set, 0, 0, &to);
  if(sval == 0)
    /* timeout */
    ret_val = FALSE;
  
  return ret_val;
}

/*
 * Given one filled in connection struct (named needle), this function should
 * detect if there already is one that have all the significant details
 * exactly the same and thus should be used instead.
 */
static bool
ConnectionExists(struct SessionHandle *data,
                 struct connectdata *needle,
                 struct connectdata **usethis)
{
  long i;
  struct connectdata *check;

  for(i=0; i< data->state.numconnects; i++) {
    bool match = FALSE;
    /*
     * Note that if we use a HTTP proxy, we check connections to that
     * proxy and not to the actual remote server.
     */
    check = data->state.connects[i];
    if(!check)
      /* NULL pointer means not filled-in entry */
      continue;
    if(!needle->bits.httpproxy || needle->protocol&PROT_SSL) {
      /* The requested connection does not use a HTTP proxy or it
         uses SSL. */

      if(!(needle->protocol&PROT_SSL) && check->bits.httpproxy)
        /* we don't do SSL but the cached connection has a proxy,
           then don't match this */
        continue;

      if(strequal(needle->protostr, check->protostr) &&
         strequal(needle->name, check->name) &&
         (needle->remote_port == check->remote_port) ) {
        if(strequal(needle->protostr, "FTP")) {
          /* This is FTP, verify that we're using the same name and
             password as well */
          if(!strequal(needle->data->state.user, check->proto.ftp->user) ||
             !strequal(needle->data->state.passwd, check->proto.ftp->passwd)) {
            /* one of them was different */
            continue;
          }
        }
        match = TRUE;
      }
    }
    else { /* The requested needle connection is using a proxy,
              is the checked one using the same? */
      if(check->bits.httpproxy &&
         strequal(needle->proxyhost, check->proxyhost) &&
         needle->port == check->port) {
        /* This is the same proxy connection, use it! */
        match = TRUE;
      }
    }

    if(match) {
      bool dead = SocketIsDead(check->firstsocket);
      if(dead) {
        /*
         */
        infof(data, "Connection %d seems to be dead!\n", i);
        Curl_disconnect(check); /* disconnect resources */
        data->state.connects[i]=NULL; /* nothing here */

        /* There's no need to continue searching, because we only store
           one connection for each unique set of identifiers */
        return FALSE;
      }

      *usethis = check;
      return TRUE; /* yes, we found one to use! */
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
ConnectionKillOne(struct SessionHandle *data)
{
  long i;
  struct connectdata *conn;
  int highscore=-1;
  int connindex=-1;
  int score;
  CURLcode result;
  struct timeval now;

  now = Curl_tvnow();

  for(i=0; i< data->state.numconnects; i++) {
    conn = data->state.connects[i];
    
    if(!conn)
      continue;

    /*
     * By using the set policy, we score each connection.
     */
    switch(data->set.closepolicy) {
    case CURLCLOSEPOLICY_LEAST_RECENTLY_USED:
    default:
      /*
       * Set higher score for the age passed since the connection
       * was used.
       */
      score = Curl_tvdiff(now, conn->now);
      break;
    case CURLCLOSEPOLICY_OLDEST:
      /*
       * Set higher score for the age passed since the connection
       * was created.
       */
      score = Curl_tvdiff(now, conn->created);
      break;
    }

    if(score > highscore) {
      highscore = score;
      connindex = i;
    }
  }
  if(connindex >= 0) {

    /* the winner gets the honour of being disconnected */
    result = Curl_disconnect(data->state.connects[connindex]);

    /* clean the array entry */
    data->state.connects[connindex] = NULL;
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
ConnectionStore(struct SessionHandle *data,
                struct connectdata *conn)
{
  long i;
  for(i=0; i< data->state.numconnects; i++) {
    if(!data->state.connects[i])
      break;
  }
  if(i == data->state.numconnects) {
    /* there was no room available, kill one */
    i = ConnectionKillOne(data);
    infof(data, "Connection (#%d) was killed to make room\n", i);
  }

  if(-1 != i) {
    /* only do this if a true index was returned, if -1 was returned there
       is no room in the cache for an unknown reason and we cannot store
       this there. */
    data->state.connects[i] = conn; /* fill in this */
    conn->connectindex = i; /* make the child know where the pointer to this
                               particular data is stored */
  }
  return i;
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifies the final
 * desitination server.
 */
static int handleSock5Proxy(
    const char *proxy_name,
    const char *proxy_password,
    struct connectdata *conn,
    int sock)
{
  unsigned char socksreq[600]; /* room for large user/pw (255 max each) */
  int actualread;
  int written;
  CURLcode result;

  Curl_nonblock(sock, FALSE);

  socksreq[0] = 5; /* version */
  socksreq[1] = (char)(proxy_name[0] ? 2 : 1); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 2; /* username/password */

  result = Curl_write(conn, sock, (char *)socksreq, (2 + (int)socksreq[1]),
                      &written);
  if ((result != CURLE_OK) || (written != (2 + (int)socksreq[1]))) {
    failf(conn->data, "Unable to send initial SOCKS5 request.");
    return 1;
  }

  result=Curl_read(conn, sock, (char *)socksreq, 2, &actualread);
  if ((result != CURLE_OK) || (actualread != 2)) {
    failf(conn->data, "Unable to receive initial SOCKS5 response.");
    return 1;
  }

  if (socksreq[0] != 5) {
    failf(conn->data, "Received invalid version in initial SOCKS5 response.");
    return 1;
  }
  if (socksreq[1] == 0) {
    /* Nothing to do, no authentication needed */
    ;
  }
  else if (socksreq[1] == 2) {
    /* Needs user name and password */
    int userlen, pwlen, len;

    userlen = strlen(proxy_name);
    pwlen = strlen(proxy_password);

    /*   username/password request looks like
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */
    len = 0;
    socksreq[len++] = 1;    /* username/pw subnegotiation version */
    socksreq[len++] = (char) userlen;
    memcpy(socksreq + len, proxy_name, (int) userlen);
    len += userlen;
    socksreq[len++] = (char) pwlen;
    memcpy(socksreq + len, proxy_password, (int) pwlen);
    len += pwlen;

    result = Curl_write(conn, sock, (char *)socksreq, len, &written);
    if ((result != CURLE_OK) || (len != written)) {
      failf(conn->data, "Failed to send SOCKS5 sub-negotiation request.");
      return 1;
    }

    result=Curl_read(conn, sock, (char *)socksreq, 2, &actualread);
    if ((result != CURLE_OK) || (actualread != 2)) {
      failf(conn->data, "Unable to receive SOCKS5 sub-negotiation response.");
      return 1;
    }

    if ((socksreq[0] != 5) || /* version */
        (socksreq[1] != 0)) { /* status */
      failf(conn->data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return 1;
    }

    /* Everything is good so far, user was authenticated! */
  }
  else {
    /* error */
    if (socksreq[1] == 1) {
      failf(conn->data,
            "SOCKS5 GSSAPI per-message authentication is not supported.");
      return 1;
    }
    else if (socksreq[1] == 255) {
      if (proxy_name[0] == 0) {
        failf(conn->data,
              "No authentication method was acceptable. (It is quite likely"
              " that the SOCKS5 server wanted a username/password, since none"
              " was supplied to the server on this connection.)");
      }
      else {            
        failf(conn->data, "No authentication method was acceptable.");
      }
      return 1;
    }
    else {
      failf(conn->data,
            "Undocumented SOCKS5 mode attempted to be used by server.");
      return 1;
    }
  }

  /* Authentication is complete, now specify destination to the proxy */
  socksreq[0] = 5; /* version (SOCKS5) */
  socksreq[1] = 1; /* connect */
  socksreq[2] = 0; /* must be zero */
  socksreq[3] = 1; /* IPv4 = 1 */
    
  {
#ifndef ENABLE_IPV6
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    dns = Curl_resolv(conn->data, conn->hostname, conn->remote_port);
    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if (hp && hp->h_addr_list[0]) {
      socksreq[4] = ((char*)hp->h_addr_list[0])[0];
      socksreq[5] = ((char*)hp->h_addr_list[0])[1];
      socksreq[6] = ((char*)hp->h_addr_list[0])[2];
      socksreq[7] = ((char*)hp->h_addr_list[0])[3];

      Curl_resolv_unlock(dns); /* not used anymore from now on */
    }
    else {
      failf(conn->data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            conn->hostname);
      return 1;
    }
#else
    failf(conn->data,
          "%s:%d has an internal error an needs to be fixed to work",
          __FILE__, __LINE__);
    return 1;
#endif
  }

  *((unsigned short*)&socksreq[8]) = htons(conn->remote_port);

  {
    const int packetsize = 10;

    result = Curl_write(conn, sock, (char *)socksreq, packetsize, &written);
    if ((result != CURLE_OK) || (written != packetsize)) {
      failf(conn->data, "Failed to send SOCKS5 connect request.");
      return 1;
    }

    result = Curl_read(conn, sock, (char *)socksreq, packetsize, &actualread);
    if ((result != CURLE_OK) || (actualread != packetsize)) {
      failf(conn->data, "Failed to receive SOCKS5 connect request ack.");
      return 1;
    }

    if (socksreq[0] != 5) { /* version */
      failf(conn->data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return 1;
    }
    if (socksreq[1] != 0) { /* Anything besides 0 is an error */
        failf(conn->data,
              "Can't complete SOCKS5 connection to %d.%d.%d.%d:%d. (%d)",
              (unsigned char)socksreq[4], (unsigned char)socksreq[5],
              (unsigned char)socksreq[6], (unsigned char)socksreq[7],
              (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
              socksreq[1]);
        return 1;
    }
  }

  Curl_nonblock(sock, TRUE);
  return 0; /* Proxy was successful! */
}

static CURLcode ConnectPlease(struct connectdata *conn,
                              struct Curl_dns_entry *hostaddr,
                              bool *connected)
{
  CURLcode result;
  Curl_ipconnect *addr;

  /*************************************************************
   * Connect to server/proxy
   *************************************************************/
  result= Curl_connecthost(conn,
                           hostaddr,
                           conn->port,
                           &conn->firstsocket,
                           &addr,
                           connected);
  if(CURLE_OK == result) {
    /* All is cool, then we store the current information from the hostaddr
       struct to the serv_addr, as it might be needed later. The address
       returned from the function above is crucial here. */
    conn->connect_addr = hostaddr;

#ifdef ENABLE_IPV6
    conn->serv_addr = addr;
#else
    memset((char *) &conn->serv_addr, '\0', sizeof(conn->serv_addr));
    memcpy((char *)&(conn->serv_addr.sin_addr),
           (struct in_addr *)addr, sizeof(struct in_addr));
    conn->serv_addr.sin_family = hostaddr->addr->h_addrtype;
    conn->serv_addr.sin_port = htons((unsigned short)conn->port);
#endif

    if (conn->data->set.proxytype == CURLPROXY_SOCKS5) {
      return handleSock5Proxy(conn->data->state.proxyuser,
                              conn->data->state.proxypasswd,
                              conn,
                              conn->firstsocket) ?
        CURLE_COULDNT_CONNECT : CURLE_OK;
    }
    else if (conn->data->set.proxytype == CURLPROXY_HTTP) {
      /* do nothing here. handled later. */
    }
    else {
      failf(conn->data, "unknown proxytype option given");
      return CURLE_COULDNT_CONNECT; 
    }
  }

  return result;
}

static void verboseconnect(struct connectdata *conn,
                           struct Curl_dns_entry *dns)
{
#ifdef HAVE_INET_NTOA_R
  char ntoa_buf[64];
#endif
  struct SessionHandle *data = conn->data;

  /* Figure out the ip-number and display the first host name it shows: */
#ifdef ENABLE_IPV6
  (void)dns; /* not used in the IPv6 enabled version */
  {
    char hbuf[NI_MAXHOST];
#ifdef NI_WITHSCOPEID
    const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
    const int niflags = NI_NUMERICHOST;
#endif
    struct addrinfo *ai = conn->serv_addr;

    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf), NULL, 0,
	niflags)) {
      snprintf(hbuf, sizeof(hbuf), "?");
    }
    if (ai->ai_canonname) {
      infof(data, "Connected to %s (%s) port %d\n", ai->ai_canonname, hbuf,
            conn->port);
    } else {
      infof(data, "Connected to %s port %d\n", hbuf, conn->port);
    }
  }
#else
  {
    Curl_addrinfo *hostaddr=dns->addr;
    struct in_addr in;
    (void) memcpy(&in.s_addr, &conn->serv_addr.sin_addr, sizeof (in.s_addr));
    infof(data, "Connected to %s (%s) port %d\n",
          hostaddr?hostaddr->h_name:"",
#if defined(HAVE_INET_NTOA_R)
          inet_ntoa_r(in, ntoa_buf, sizeof(ntoa_buf)),
#else
          inet_ntoa(in),
#endif
          conn->port);
  }
#endif
}

/*
 * We have discovered that the TCP connection has been successful, we can now
 * proceed with some action.
 *
 * If we're using the multi interface, this host address pointer is most
 * likely NULL at this point as we can't keep the resolved info around. This
 * may call for some reworking, like a reference counter in the struct or
 * something. The hostaddr is not used for very much though, we have the
 * 'serv_addr' field in the connectdata struct for most of it.
 */
CURLcode Curl_protocol_connect(struct connectdata *conn,
                               struct Curl_dns_entry *hostaddr)
{
  struct SessionHandle *data = conn->data;
  CURLcode result=CURLE_OK;
  
  Curl_pgrsTime(data, TIMER_CONNECT); /* connect done */

  if(data->set.verbose)
    verboseconnect(conn, hostaddr);

  if(conn->curl_connect) {
    /* is there a protocol-specific connect() procedure? */

    /* set start time here for timeout purposes in the
     * connect procedure, it is later set again for the
     * progress meter purpose */
    conn->now = Curl_tvnow();

    /* Call the protocol-specific connect function */
    result = conn->curl_connect(conn);
  }

  return result; /* pass back status */
}

static CURLcode CreateConnection(struct SessionHandle *data,
                                 struct connectdata **in_connect)
{
  char *tmp;
  char *buf;
  CURLcode result=CURLE_OK;
  char resumerange[40]="";
  struct connectdata *conn;
  struct connectdata *conn_temp;
  int urllen;
  struct Curl_dns_entry *hostaddr;
#ifdef HAVE_ALARM
  unsigned int prev_alarm=0;
#endif
  char endbracket;

#ifdef HAVE_SIGACTION
  struct sigaction keep_sigact;   /* store the old struct here */
  bool keep_copysig=FALSE;        /* did copy it? */
#else
#ifdef HAVE_SIGNAL
  void *keep_sigact;              /* store the old handler here */
#endif
#endif

  /*************************************************************
   * Check input data
   *************************************************************/

  if(!data->change.url)
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
  conn->firstsocket = -1;     /* no file descriptor */
  conn->secondarysocket = -1; /* no file descriptor */
  conn->connectindex = -1;    /* no index */
  conn->bits.httpproxy = (data->change.proxy && *data->change.proxy &&
                          (data->set.proxytype == CURLPROXY_HTTP))?
    TRUE:FALSE; /* http proxy or not */
  conn->bits.use_range = data->set.set_range?TRUE:FALSE; /* range status */
  conn->range = data->set.set_range;              /* clone the range setting */
  conn->resume_from = data->set.set_resume_from;   /* inherite resume_from */

  /* Default protocol-independent behavior doesn't support persistant
     connections, so we set this to force-close. Protocols that support
     this need to set this to FALSE in their "curl_do" functions. */
  conn->bits.close = TRUE;

  /* inherite initial knowledge from the data struct */
  conn->bits.user_passwd = data->set.userpwd?1:0;
  conn->bits.proxy_user_passwd = data->set.proxyuserpwd?1:0;

  /* maxdownload must be -1 on init, as 0 is a valid value! */
  conn->maxdownload = -1;  /* might have been used previously! */

  /* Store creation time to help future close decision making */
  conn->created = Curl_tvnow();

  /* Set the start time temporary to this creation time to allow easier
     timeout checks before the transfer has started for real. The start time
     is later set "for real" using Curl_pgrsStartNow(). */
  conn->data->progress.start = conn->created; 

  conn->bits.upload_chunky =
    ((conn->protocol&PROT_HTTP) &&
     data->set.upload &&
     (data->set.infilesize == -1) &&
     (data->set.httpversion != CURL_HTTP_VERSION_1_0))?
    /* HTTP, upload, unknown file size and not HTTP 1.0 */
    TRUE:
  /* else, no chunky upload */
  FALSE;

  /***********************************************************
   * We need to allocate memory to store the path in. We get the size of the
   * full URL to be sure, and we need to make it at least 256 bytes since
   * other parts of the code will rely on this fact
   ***********************************************************/
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->change.url);
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
  if((2 == sscanf(data->change.url, "%64[^:]://%[^\n]",
                  conn->protostr,
                  conn->path)) && strequal(conn->protostr, "file")) {
    /*
     * we deal with file://<host>/<path> differently since it supports no
     * hostname other than "localhost" and "127.0.0.1", which is unique among
     * the URL protocols specified in RFC 1738
     */
    if(conn->path[0] != '/') {
      /* the URL included a host name, we ignore host names in file:// URLs
         as the standards don't define what to do with them */
      char *ptr=strchr(conn->path, '/');
      if(ptr) {
        /* there was a slash present
           
           RFC1738 (section 3.1, page 5) says:
 
           The rest of the locator consists of data specific to the scheme,
           and is known as the "url-path". It supplies the details of how the
           specified resource can be accessed. Note that the "/" between the
           host (or port) and the url-path is NOT part of the url-path.
 
           As most agents use file://localhost/foo to get '/foo' although the
           slash preceeding foo is a separator and not a slash for the path,
           a URL as file://localhost//foo must be valid as well, to refer to
           the same file with an absolute path.
        */

        if(ptr[1] && ('/' == ptr[1]))
          /* if there was two slashes, we skip the first one as that is then
             used truly as a separator */
          ptr++; 
        
        strcpy(conn->path, ptr);
      }
    }

    strcpy(conn->protostr, "file"); /* store protocol string lowercase */
  }
  else {
    /* Set default host and default path */
    strcpy(conn->gname, "curl.haxx.se");
    strcpy(conn->path, "/");

    if (2 > sscanf(data->change.url,
                   "%64[^\n:]://%512[^\n/]%[^\n]",
                   conn->protostr, conn->gname, conn->path)) {
      
      /*
       * The URL was badly formatted, let's try the browser-style _without_
       * protocol specified like 'http://'.
       */
      if((1 > sscanf(data->change.url, "%512[^\n/]%[^\n]",
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

      /* Note: if you add a new protocol, please update the list in
       * lib/version.c too! */

      if(checkprefix("FTP", conn->gname)) {
        strcpy(conn->protostr, "ftp");
      }
      else if(checkprefix("GOPHER", conn->gname))
        strcpy(conn->protostr, "gopher");
#ifdef USE_SSLEAY
      else if(checkprefix("HTTPS", conn->gname))
        strcpy(conn->protostr, "https");
      else if(checkprefix("FTPS", conn->gname))
        strcpy(conn->protostr, "ftps");
#endif /* USE_SSLEAY */
      else if(checkprefix("TELNET", conn->gname))
        strcpy(conn->protostr, "telnet");
      else if (checkprefix("DICT", conn->gname))
        strcpy(conn->protostr, "DICT");
      else if (checkprefix("LDAP", conn->gname))
        strcpy(conn->protostr, "LDAP");
      else {
        strcpy(conn->protostr, "http");
      }

      conn->protocol |= PROT_MISSING; /* not given in URL */
    }
  }

  buf = data->state.buffer; /* this is our buffer */

  /*
   * So if the URL was A://B/C,
   *   conn->protostr is A
   *   conn->gname is B
   *   conn->path is /C
   */

  /*************************************************************
   * Take care of proxy authentication stuff
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    data->state.proxyuser[0] =0;
    data->state.proxypasswd[0]=0;

    if(*data->set.proxyuserpwd != ':') {
      /* the name is given, get user+password */
      sscanf(data->set.proxyuserpwd, "%127[^:]:%127[^\n]",
             data->state.proxyuser, data->state.proxypasswd);
      }
    else
      /* no name given, get the password only */
      sscanf(data->set.proxyuserpwd+1, "%127[^\n]", data->state.proxypasswd);

    /* check for password, if no ask for one */
    if( !data->state.proxypasswd[0] ) {
      if(data->set.fpasswd( data->set.passwd_client,
                            "proxy password:",
                            data->state.proxypasswd,
                            sizeof(data->state.proxypasswd))) {
        failf(data, "Bad password from password callback");
        return CURLE_BAD_PASSWORD_ENTERED;
      }
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
  if(!data->change.proxy) {
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
    char *no_proxy_tok_buf;
    char *proxy=NULL;
    char proxy_env[128];

    no_proxy=curl_getenv("no_proxy");
    if(!no_proxy)
      no_proxy=curl_getenv("NO_PROXY");

    if(!no_proxy || !strequal("*", no_proxy)) {
      /* NO_PROXY wasn't specified or it wasn't just an asterisk */
      char *nope;

      nope=no_proxy?strtok_r(no_proxy, ", ", &no_proxy_tok_buf):NULL;
      while(nope) {
        unsigned int namelen;
        char *endptr = strchr(conn->name, ':');
        if(endptr)
          namelen=endptr-conn->name;
        else
          namelen=strlen(conn->name);

        if(strlen(nope) <= namelen) {
          char *checkn=
            conn->name + namelen - strlen(nope);
          if(checkprefix(nope, checkn)) {
            /* no proxy for this host! */
            break;
          }
        }
	nope=strtok_r(NULL, ", ", &no_proxy_tok_buf);
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

        /*
         * We don't try the uppercase version of HTTP_PROXY because of
         * security reasons:
         *
         * When curl is used in a webserver application
         * environment (cgi or php), this environment variable can
         * be controlled by the web server user by setting the
         * http header 'Proxy:' to some value.
         * 
         * This can cause 'internal' http/ftp requests to be
         * arbitrarily redirected by any external attacker.
         */
	if(!prox && !strequal("http_proxy", proxy_env)) {
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
          data->change.proxy = proxy;
          data->change.proxy_alloc=TRUE; /* this needs to be freed later */
          conn->bits.httpproxy = TRUE;
        }
      } /* if (!nope) - it wasn't specified non-proxy */
    } /* NO_PROXY wasn't specified or '*' */
    if(no_proxy)
      free(no_proxy);
  } /* if not using proxy */

  /*************************************************************
   * No protocol part in URL was used, add it!
   *************************************************************/
  if(conn->protocol&PROT_MISSING) {
    /* We're guessing prefixes here and if we're told to use a proxy or if
       we're gonna follow a Location: later or... then we need the protocol
       part added so that we have a valid URL. */
    char *reurl;

    reurl = aprintf("%s://%s", conn->protostr, data->change.url);

    if(!reurl)
      return CURLE_OUT_OF_MEMORY;

    data->change.url = reurl;
    data->change.url_alloc = TRUE; /* free this later */
    conn->protocol &= ~PROT_MISSING; /* switch that one off again */
  }

#ifndef CURL_DISABLE_HTTP
  /************************************************************
   * RESUME on a HTTP page is a tricky business. First, let's just check that
   * 'range' isn't used, then set the range parameter and leave the resume as
   * it is to inform about this situation for later use. We will then
   * "attempt" to resume, and if we're talking to a HTTP/1.1 (or later)
   * server, we will get the document resumed. If we talk to a HTTP/1.0
   * server, we just fail since we can't rewind the file writing from within
   * this function.
   ***********************************************************/
  if(conn->resume_from) {
    if(!conn->bits.use_range) {
      /* if it already was in use, we just skip this */
      snprintf(resumerange, sizeof(resumerange), "%d-", conn->resume_from);
      conn->range=strdup(resumerange); /* tell ourselves to fetch this range */
      conn->bits.rangestringalloc = TRUE; /* mark as allocated */
      conn->bits.use_range = 1; /* switch on range usage */
    }
  }
#endif
  /*************************************************************
   * Setup internals depending on protocol
   *************************************************************/

  if (strequal(conn->protostr, "HTTP")) {
#ifndef CURL_DISABLE_HTTP
    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_HTTP;
    conn->remote_port = PORT_HTTP;
    conn->protocol |= PROT_HTTP;
    conn->curl_do = Curl_http;
    conn->curl_do_more = NULL;
    conn->curl_done = Curl_http_done;
    conn->curl_connect = Curl_http_connect;
#else
    failf(data, LIBCURL_NAME
          " was built with HTTP disabled, http: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }
  else if (strequal(conn->protostr, "HTTPS")) {
#if defined(USE_SSLEAY) && !defined(CURL_DISABLE_HTTP)

    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_HTTPS;
    conn->remote_port = PORT_HTTPS;
    conn->protocol |= PROT_HTTP|PROT_HTTPS|PROT_SSL;

    conn->curl_do = Curl_http;
    conn->curl_do_more = NULL;
    conn->curl_done = Curl_http_done;
    conn->curl_connect = Curl_http_connect;

#else /* USE_SSLEAY */
    failf(data, LIBCURL_NAME
          " was built with SSL disabled, https: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
  }
  else if (strequal(conn->protostr, "GOPHER")) {
#ifndef CURL_DISABLE_GOPHER
    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_GOPHER;
    conn->remote_port = PORT_GOPHER;
    /* Skip /<item-type>/ in path if present */
    if (isdigit((int)conn->path[1])) {
      conn->ppath = strchr(&conn->path[1], '/');
      if (conn->ppath == NULL)
	conn->ppath = conn->path;
      }
    conn->protocol |= PROT_GOPHER;
    conn->curl_do = Curl_http;
    conn->curl_do_more = NULL;
    conn->curl_done = Curl_http_done;
#else
    failf(data, LIBCURL_NAME
          " was built with GOPHER disabled, gopher: not supported!");
#endif
  }
  else if(strequal(conn->protostr, "FTP") ||
          strequal(conn->protostr, "FTPS")) {

/* MN 06/07/02 */
#ifndef CURL_DISABLE_FTP
    char *type;

    if(strequal(conn->protostr, "FTPS")) {
#ifdef USE_SSLEAY
      conn->protocol |= PROT_FTPS|PROT_SSL;
#else
      failf(data, LIBCURL_NAME
            " was built with SSL disabled, ftps: not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
    }

    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_FTP;
    conn->remote_port = PORT_FTP;
    conn->protocol |= PROT_FTP;

    if(data->change.proxy &&
       *data->change.proxy &&
       !data->set.tunnel_thru_httpproxy) {
      /* Unless we have asked to tunnel ftp operations through the proxy, we
         switch and use HTTP operations only */
      if(conn->protocol & PROT_FTPS) {
        /* FTPS is a hacked protocol and does not work through your
           ordinary http proxy! */
        failf(data, "ftps does not work through http proxy!");
        return CURLE_UNSUPPORTED_PROTOCOL;
      }
#ifndef CURL_DISABLE_HTTP
      conn->curl_do = Curl_http;
      conn->curl_done = Curl_http_done;
#else
      failf(data, "FTP over http proxy requires HTTP support built-in!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif
    }
    else {
      conn->curl_do = Curl_ftp;
      conn->curl_do_more = Curl_ftp_nextconnect;
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
      *type=0;                     /* it was in the middle of the hostname */
      command = toupper(type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
	data->set.ftp_ascii = 1;
	break;
      case 'D': /* directory mode */
	data->set.ftp_list_only = 1;
	break;
      case 'I': /* binary mode */
      default:
	/* switch off ASCII */
	data->set.ftp_ascii = 0;
	break;
      }
    }

/* MN 06/07/02 */
#else /* CURL_DISABLE_FTP */
    failf(data, LIBCURL_NAME
          " was built with FTP disabled, ftp/ftps: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }
  else if(strequal(conn->protostr, "TELNET")) {
#ifndef CURL_DISABLE_TELNET
    /* telnet testing factory */
    conn->protocol |= PROT_TELNET;

    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port: PORT_TELNET;
    conn->remote_port = PORT_TELNET;
    conn->curl_do = Curl_telnet;
    conn->curl_done = Curl_telnet_done;
#else
    failf(data, LIBCURL_NAME
          " was built with TELNET disabled!");
#endif
  }
  else if (strequal(conn->protostr, "DICT")) {
#ifndef CURL_DISABLE_DICT
    conn->protocol |= PROT_DICT;
    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_DICT;
    conn->remote_port = PORT_DICT;
    conn->curl_do = Curl_dict;
    conn->curl_done = NULL; /* no DICT-specific done */
#else
    failf(data, LIBCURL_NAME
          " was built with DICT disabled!");
#endif
  }
  else if (strequal(conn->protostr, "LDAP")) {
#ifndef CURL_DISABLE_LDAP
    conn->protocol |= PROT_LDAP;
    conn->port = (data->set.use_port && data->state.allow_port)?
      data->set.use_port:PORT_LDAP;
    conn->remote_port = PORT_LDAP;
    conn->curl_do = Curl_ldap;
    conn->curl_done = NULL; /* no LDAP-specific done */
#else
    failf(data, LIBCURL_NAME
          " was built with LDAP disabled!");
#endif
  }
  else if (strequal(conn->protostr, "FILE")) {
#ifndef CURL_DISABLE_FILE
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
#else
    failf(data, LIBCURL_NAME
          " was built with FILE disabled!");
#endif
  }
  else {
    /* We fell through all checks and thus we don't support the specified
       protocol */
    failf(data, "Unsupported protocol: %s", conn->protostr);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  /*************************************************************
   * Figure out the remote port number
   *
   * No matter if we use a proxy or not, we have to figure out the remote
   * port number of various reasons.
   *
   * To be able to detect port number flawlessly, we must not confuse them
   * IPv6-specified addresses in the [0::1] style. (RFC2732)
   *
   * The conn->name is currently [user:passwd@]host[:port] where host could
   * be a hostname, IPv4 address or IPv6 address.
   *************************************************************/
  if((1 == sscanf(conn->name, "[%*39[0-9a-fA-F:.]%c", &endbracket)) &&
     (']' == endbracket)) {
    /* this is a RFC2732-style specified IP-address */
    conn->bits.ipv6_ip = TRUE;

    conn->name++; /* pass the starting bracket */ 
    conn->hostname++;
    tmp = strchr(conn->name, ']');
    *tmp = 0; /* zero terminate */
    tmp++; /* pass the ending bracket */
    if(':' != *tmp)
      tmp = NULL; /* no port number available */
  }
  else
    tmp = strrchr(conn->name, ':');

  if (tmp) {
    char *rest;
    unsigned long port;

    port=strtoul(tmp+1, &rest, 10);  /* Port number must be decimal */

    if (rest != (tmp+1) && *rest == '\0') {
      /* The colon really did have only digits after it,
       * so it is either a port number or a mistake */

      if (port > 0xffff) {   /* Single unix standard says port numbers are
                              * 16 bits long */
        failf(data, "Port number too large: %lu", port);
        return CURLE_URL_MALFORMAT;
      }

      *tmp = '\0'; /* cut off the name there */
      conn->remote_port = (unsigned short)port;
    }
  }

  if(data->change.proxy && *data->change.proxy) {
    /* If this is supposed to use a proxy, we need to figure out the proxy
       host name name, so that we can re-use an existing connection
       that may exist registered to the same proxy host. */

    char *prox_portno;
    char *endofprot;

    /* We need to make a duplicate of the proxy so that we can modify the
       string safely. */
    char *proxydup=strdup(data->change.proxy);

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
    else if(data->set.proxyport) {
      /* None given in the proxy string, then get the default one if it is
         given */
      conn->port = data->set.proxyport;
    }

    /* now, clone the cleaned proxy host name */
    conn->proxyhost = strdup(proxyptr);

    free(proxydup); /* free the duplicate pointer and not the modified */
  }

  /*************************************************************
   * Take care of user and password authentication stuff
   *************************************************************/

  /*
   * Inputs: data->set.userpwd   (CURLOPT_USERPWD)
   *         data->set.fpasswd   (CURLOPT_PASSWDFUNCTION)
   *         data->set.use_netrc (CURLOPT_NETRC)
   *         conn->hostname
   *         netrc file
   *         hard-coded defaults
   *
   * Outputs: (almost :- all currently undefined)
   *          conn->bits.user_passwd  - non-zero if non-default passwords exist
   *          conn->state.user        - non-zero length if defined
   *          conn->state.passwd      -   ditto
   *          conn->hostname          - remove user name and password
   */

  /* At this point, we're hoping all the other special cases have
   * been taken care of, so conn->hostname is at most
   *    [user[:password]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */

  data->state.user[0] =0;   /* to make everything well-defined */
  data->state.passwd[0]=0;
  
  if (conn->protocol & (PROT_FTP|PROT_HTTP)) {
    /* This is a FTP or HTTP URL, we will now try to extract the possible
     * user+password pair in a string like:
     * ftp://user:password@ftp.my.site:8021/README */
    char *ptr=strchr(conn->name, '@');
    char *userpass = conn->name;
    if(ptr != NULL) {
      /* there's a user+password given here, to the left of the @ */

      conn->name = conn->hostname = ++ptr;

      /* So the hostname is sane.  Only bother interpreting the
       * results if we could care.  It could still be wasted
       * work because it might be overtaken by the programmatically
       * set user/passwd, but doing that first adds more cases here :-(
       */

      if (data->set.use_netrc != CURL_NETRC_REQUIRED) {
        /* We could use the one in the URL */

        conn->bits.user_passwd = 1; /* enable user+password */

        if(*userpass != ':') {
          /* the name is given, get user+password */
          sscanf(userpass, "%127[^:@]:%127[^@]",
                 data->state.user, data->state.passwd);
        }
        else
          /* no name given, get the password only */
          sscanf(userpass, ":%127[^@]", data->state.passwd);

        if(data->state.user[0]) {
          char *newname=curl_unescape(data->state.user, 0);
          if(strlen(newname) < sizeof(data->state.user)) {
            strcpy(data->state.user, newname);
          }
          /* if the new name is longer than accepted, then just use
             the unconverted name, it'll be wrong but what the heck */
          free(newname);
        }
        if (data->state.passwd[0]) {
          /* we have a password found in the URL, decode it! */
          char *newpasswd=curl_unescape(data->state.passwd, 0);
          if(strlen(newpasswd) < sizeof(data->state.passwd)) {
            strcpy(data->state.passwd, newpasswd);
          }
          free(newpasswd);
        }
      }
    }
  }

  /* Programmatically set password:
   *   - always applies, if available
   *   - takes precedence over the values we just set above
   * so scribble it over the top.
   * User-supplied passwords are assumed not to need unescaping.
   *
   * user_password is set in "inherite initial knowledge' above,
   * so it doesn't have to be set in this block
   */
  if (data->set.userpwd != NULL) {
    if(*data->set.userpwd != ':') {
      /* the name is given, get user+password */
      sscanf(data->set.userpwd, "%127[^:]:%127[^\n]",
             data->state.user, data->state.passwd);
    }
    else
      /* no name given, get the password only */
      sscanf(data->set.userpwd+1, "%127[^\n]", data->state.passwd);
  }

  if (data->set.use_netrc != CURL_NETRC_IGNORED &&
      data->state.passwd[0] == '\0' ) {  /* need passwd */
    if(Curl_parsenetrc(conn->hostname,
                       data->state.user,
                       data->state.passwd)) {
      infof(data, "Couldn't find host %s in the .netrc file, using defaults",
            conn->hostname);
    } else
      conn->bits.user_passwd = 1; /* enable user+password */
  }

  /* if we have a user but no password, ask for one */
  if(conn->bits.user_passwd &&
     !data->state.passwd[0] ) {
    if(data->set.fpasswd(data->set.passwd_client,
                         "password:", data->state.passwd,
                         sizeof(data->state.passwd)))
      return CURLE_BAD_PASSWORD_ENTERED;
  }

  /* So we could have a password but no user; that's just too bad. */

  /* If our protocol needs a password and we have none, use the defaults */
  if ( (conn->protocol & (PROT_FTP|PROT_HTTP)) &&
       !conn->bits.user_passwd) {
    strcpy(data->state.user, CURL_DEFAULT_USER);
    strcpy(data->state.passwd, CURL_DEFAULT_PASSWORD);
    /* This is the default password, so DON'T set conn->bits.user_passwd */
  }

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  /* reuse_fresh is set TRUE if we are told to use a fresh connection
     by force */
  if(!data->set.reuse_fresh &&
     ConnectionExists(data, conn, &conn_temp)) {
    /*
     * We already have a connection for this, we got the former connection
     * in the conn_temp variable and thus we need to cleanup the one we
     * just allocated before we can move along and use the previously
     * existing one.
     */
    struct connectdata *old_conn = conn;
    char *path = old_conn->path; /* setup the current path pointer properly */
    char *ppath = old_conn->ppath; /* this is the modified path pointer */
    if(old_conn->proxyhost)
      free(old_conn->proxyhost);
    conn = conn_temp;        /* use this connection from now on */

    /* If we speak over a proxy, we need to copy the host name too, as it
       might be another remote host even when re-using a connection */
    strcpy(conn->gname, old_conn->gname); /* safe strcpy() */

    /* we need these pointers if we speak over a proxy */
    conn->hostname = conn->gname;
    conn->name = &conn->gname[old_conn->name - old_conn->gname];

    free(conn->path);    /* free the previously allocated path pointer */

    /* 'path' points to the allocated data, 'ppath' may have been advanced
       to point somewhere within the 'path' area. */
    conn->path = path; 
    conn->ppath = ppath;

    /* re-use init */
    conn->bits.reuse = TRUE; /* yes, we're re-using here */
    conn->bits.chunk = FALSE; /* always assume not chunked unless told
                                 otherwise */
    conn->maxdownload = -1;  /* might have been used previously! */

    free(old_conn);          /* we don't need this anymore */

    /*
     * If we're doing a resumed transfer, we need to setup our stuff
     * properly.
     */
    conn->resume_from = data->set.set_resume_from;
    if (conn->resume_from) {
        snprintf(resumerange, sizeof(resumerange), "%d-", conn->resume_from);
        if (conn->bits.rangestringalloc == TRUE) 
            free(conn->range);
        
        /* tell ourselves to fetch this range */
        conn->range = strdup(resumerange);
        conn->bits.use_range = TRUE;        /* enable range download */
        conn->bits.rangestringalloc = TRUE; /* mark range string allocated */
    }
    else if (data->set.set_range) {
      /* There is a range, but is not a resume, useful for random ftp access */
      conn->range = strdup(data->set.set_range);
      conn->bits.rangestringalloc = TRUE; /* mark range string allocated */
      conn->bits.use_range = TRUE;        /* enable range download */
    }
    
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
   * Set timeout if that is being used
   *************************************************************/
  if((data->set.timeout || data->set.connecttimeout) && !data->set.no_signal) {
    /*************************************************************
     * Set signal handler to catch SIGALRM
     * Store the old value to be able to set it back later!
     *************************************************************/

#ifdef HAVE_SIGACTION
    struct sigaction sigact;
    sigaction(SIGALRM, NULL, &sigact);
    keep_sigact = sigact;
    keep_copysig = TRUE; /* yes, we have a copy */
    sigact.sa_handler = alarmfunc;
#ifdef SA_RESTART
    /* HPUX doesn't have SA_RESTART but defaults to that behaviour! */
    sigact.sa_flags &= ~SA_RESTART;
#endif
    /* now set the new struct */
    sigaction(SIGALRM, &sigact, NULL);
#else
    /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
    keep_sigact = signal(SIGALRM, alarmfunc);
#endif
#endif

    /* We set the timeout on the name resolving phase first, separately from
     * the download/upload part to allow a maximum time on everything. This is
     * a signal-based timeout, why it won't work and shouldn't be used in
     * multi-threaded environments. */

#ifdef HAVE_ALARM
    /* alarm() makes a signal get sent when the timeout fires off, and that
       will abort system calls */
    prev_alarm = alarm(data->set.connecttimeout?
                       data->set.connecttimeout:
                       data->set.timeout);
    /* We can expect the conn->created time to be "now", as that was just
       recently set in the beginning of this function and nothing slow
       has been done since then until now. */
#endif
  }

  /*************************************************************
   * Resolve the name of the server or proxy
   *************************************************************/
  if(conn->bits.reuse) {
    /* re-used connection, no resolving is necessary */
    hostaddr = NULL;
  }
  else if(!data->change.proxy || !*data->change.proxy) {
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    conn->port =  conn->remote_port; /* it is the same port */

    /* Resolve target host right on */
    hostaddr = Curl_resolv(data, conn->name, conn->port);

    if(!hostaddr) {
      failf(data, "Couldn't resolve host '%s'", conn->name);
      result =  CURLE_COULDNT_RESOLVE_HOST;
      /* don't return yet, we need to clean up the timeout first */
    }
  }
  else {
    /* This is a proxy that hasn't been resolved yet. */

    /* resolve proxy */
    hostaddr = Curl_resolv(data, conn->proxyhost, conn->port);

    if(!hostaddr) {
      failf(data, "Couldn't resolve proxy '%s'", conn->proxyhost);
      result = CURLE_COULDNT_RESOLVE_PROXY;
      /* don't return yet, we need to clean up the timeout first */
    }
  }
  Curl_pgrsTime(data, TIMER_NAMELOOKUP);
#ifdef HAVE_ALARM
  if((data->set.timeout || data->set.connecttimeout) && !data->set.no_signal) {
#ifdef HAVE_SIGACTION
    if(keep_copysig) {
      /* we got a struct as it looked before, now put that one back nice
         and clean */
      sigaction(SIGALRM, &keep_sigact, NULL); /* put it back */
    }
#else
#ifdef HAVE_SIGNAL
    /* restore the previous SIGALRM handler */
    signal(SIGALRM, keep_sigact);
#endif
#endif
    /* switch back the alarm() to either zero or to what it was before minus
       the time we spent until now! */
    if(prev_alarm) {
      /* there was an alarm() set before us, now put it back */
      long elapsed_ms = Curl_tvdiff(Curl_tvnow(), conn->created);
      long alarm_set;

      /* the alarm period is counted in even number of seconds */
      alarm_set = prev_alarm - elapsed_ms/1000;

      if(alarm_set<=0) {
        /* if it turned negative, we should fire off a SIGALRM here, but we
           won't, and zero would be to switch it off so we never set it to
           less than 1! */
        alarm(1);
        result = CURLE_OPERATION_TIMEOUTED;
        failf(data, "Previous alarm fired off!");
      }
      else
        alarm(alarm_set);
    }
    else
      alarm(0); /* just shut it off */
  }
#endif
  if(result)
    return result;

  /*************************************************************
   * Proxy authentication
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    char *authorization;
    snprintf(data->state.buffer, BUFSIZE, "%s:%s",
             data->state.proxyuser, data->state.proxypasswd);
    if(Curl_base64_encode(data->state.buffer, strlen(data->state.buffer),
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
  if((conn->protocol&PROT_HTTP) ||
     (data->change.proxy && *data->change.proxy)) {
    if(data->set.useragent) {
      if(conn->allocptr.uagent)
        free(conn->allocptr.uagent);
      conn->allocptr.uagent =
        aprintf("User-Agent: %s\015\012", data->set.useragent);
    }
  }

  if(data->set.encoding) {
    if(conn->allocptr.accept_encoding)
      free(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding =
      aprintf("Accept-Encoding: %s\015\012", data->set.encoding);
  }

  conn->bytecount = 0;
  conn->headerbytecount = 0;
  
  if(-1 == conn->firstsocket) {
    bool connected;

    /* Connect only if not already connected! */
    result = ConnectPlease(conn, hostaddr, &connected);

    if(connected)
      result = Curl_protocol_connect(conn, hostaddr);

    if(CURLE_OK != result)
      return result;
  }
  else {
    Curl_pgrsTime(data, TIMER_CONNECT); /* we're connected already */
    if(data->set.verbose)
      verboseconnect(conn, hostaddr);
  }

  conn->now = Curl_tvnow(); /* time this *after* the connect is done, we
                               set this here perhaps a second time */

#ifdef __EMX__
  /* 20000330 mgs
   * the check is quite a hack...
   * we're calling _fsetmode to fix the problem with fwrite converting newline
   * characters (you get mangled text files, and corrupted binary files when
   * you download to stdout and redirect it to a file). */

  if ((data->set.out)->_handle == NULL) {
    _fsetmode(stdout, "b");
  }
#endif

  return CURLE_OK;
}

CURLcode Curl_connect(struct SessionHandle *data,
                      struct connectdata **in_connect)
{
  CURLcode code;
  struct connectdata *conn;

  /* call the stuff that needs to be called */
  code = CreateConnection(data, in_connect);

  if(CURLE_OK != code) {
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    conn = (struct connectdata *)*in_connect;
    if(conn) {
      Curl_disconnect(conn);      /* close the connection */
      *in_connect = NULL;         /* return a NULL */
    }
  }
  return code;
}

CURLcode Curl_done(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  CURLcode result;

  /* cleanups done even if the connection is re-used */

  if(conn->bits.rangestringalloc) {
    free(conn->range);
    conn->bits.rangestringalloc = FALSE;
  }

  /* Cleanup possible redirect junk */
  if(conn->newurl) {
    free(conn->newurl);
    conn->newurl = NULL;
  }

  if(conn->connect_addr)
    Curl_resolv_unlock(conn->connect_addr); /* done with this */

#if defined(MALLOCDEBUG) && defined(AGGRESIVE_TEST)
  /* scan for DNS cache entries still marked as in use */
  Curl_hash_apply(data->hostcache,
                  NULL, Curl_scan_cache_used);
#endif

  /* this calls the protocol-specific function pointer previously set */
  if(conn->curl_done)
    result = conn->curl_done(conn);
  else
    result = CURLE_OK;

  Curl_pgrsDone(conn); /* done with the operation */

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has
     forced us to close this no matter what we think.
    
     if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of all our efforts to be nice, due to protocol
     restrictions in our or the server's end */
  if(data->set.reuse_forbid ||
     ((CURLE_OK == result) && conn->bits.close))
    result = Curl_disconnect(conn); /* close the connection */
  else
    infof(data, "Connection #%d left intact\n", conn->connectindex);

  return result;
}

CURLcode Curl_do(struct connectdata **connp)
{
  CURLcode result=CURLE_OK;
  struct connectdata *conn = *connp;
  struct SessionHandle *data=conn->data;

  conn->bits.do_more = FALSE; /* by default there's no curl_do_more() to use */

  if(conn->curl_do) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->curl_do(conn);

    /* This was formerly done in transfer.c, but we better do it here */
    
    if((CURLE_SEND_ERROR == result) && conn->bits.reuse) {
      /* This was a re-use of a connection and we got a write error in the
       * DO-phase. Then we DISCONNECT this connection and have another attempt
       * to CONNECT and then DO again! The retry cannot possibly find another
       * connection to re-use, since we only keep one possible connection for
       * each.  */

      infof(data, "Re-used connection seems dead, get a new one\n");

      conn->bits.close = TRUE; /* enforce close of this connetion */
      result = Curl_done(conn);   /* we are so done with this */
      if(CURLE_OK == result) {
        /* Now, redo the connect and get a new connection */
        result = Curl_connect(data, connp);
        if(CURLE_OK == result)
          /* ... finally back to actually retry the DO phase */
          result = conn->curl_do(*connp);
      }
    }
  }
  return result;
}

CURLcode Curl_do_more(struct connectdata *conn)
{
  CURLcode result=CURLE_OK;

  if(conn->curl_do_more)
    result = conn->curl_do_more(conn);

  return result;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
