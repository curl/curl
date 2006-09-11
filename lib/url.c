/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>

#if defined(WIN32) && !defined(__CYGWIN__)
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
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

#ifdef VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif
#endif

#ifdef USE_LIBIDN
#include <idna.h>
#include <tld.h>
#include <stringprep.h>
#ifdef HAVE_IDN_FREE_H
#include <idn-free.h>
#else
void idn_free (void *ptr); /* prototype from idn-free.h, not provided by
                              libidn 0.4.5's make install! */
#endif
#ifndef HAVE_IDN_FREE
/* if idn_free() was not found in this version of libidn, use plain free()
   instead */
#define idn_free(x) (free)(x)
#endif
#endif  /* USE_LIBIDN */

#include "urldata.h"
#include "netrc.h"

#include "formdata.h"
#include "base64.h"
#include "sslgen.h"
#include "hostip.h"
#include "transfer.h"
#include "sendf.h"
#include "progress.h"
#include "cookie.h"
#include "strequal.h"
#include "strerror.h"
#include "escape.h"
#include "strtok.h"
#include "share.h"
#include "content_encoding.h"
#include "http_digest.h"
#include "http_negotiate.h"
#include "select.h"
#include "multiif.h"
#include "easyif.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "tftp.h"
#include "http.h"
#include "file.h"
#include "ldap.h"
#include "url.h"
#include "connect.h"
#include "inet_ntop.h"
#include "http_ntlm.h"
#include <ca-bundle.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#ifdef HAVE_KRB4
#include "krb4.h"
#endif
#include "memory.h"

/* The last #include file should be: */
#include "memdebug.h"

/* Local static prototypes */
static long ConnectionKillOne(struct SessionHandle *data);
static bool ConnectionExists(struct SessionHandle *data,
                             struct connectdata *needle,
                             struct connectdata **usethis);
static long ConnectionStore(struct SessionHandle *data,
                            struct connectdata *conn);
static bool IsPipeliningPossible(struct SessionHandle *handle);
static void conn_free(struct connectdata *conn);

#define MAX_PIPELINE_LENGTH 5

#ifndef USE_ARES
/* not for Win32, unless it is cygwin
   not for ares builds */
#if !defined(WIN32) || defined(__CYGWIN__)

#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
#ifdef HAVE_SIGSETJMP
extern sigjmp_buf curl_jmpenv;
#endif

#ifdef SIGALRM
static
RETSIGTYPE alarmfunc(int sig)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)sig;
#ifdef HAVE_SIGSETJMP
  siglongjmp(curl_jmpenv, 1);
#endif
  return;
}
#endif
#endif /* SIGALRM */
#endif /* USE_ARES */

void Curl_safefree(void *ptr)
{
  if(ptr)
    free(ptr);
}

static void close_connections(struct SessionHandle *data)
{
  /* Loop through all open connections and kill them one by one */
  while(-1 != ConnectionKillOne(data))
    ; /* empty loop */
}

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
  struct Curl_multi *m = data->multi;

  data->magic = 0; /* force a clear */

  if(m)
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there. */
    Curl_multi_rmeasy(data->multi, data);

  if(data->state.connc && (data->state.connc->type == CONNCACHE_PRIVATE)) {
    /* close all connections still alive that are in the private connection
       cache, as we no longer have the pointer left to the shared one. */
    close_connections(data);

    /* free the connection cache if allocated privately */
    Curl_rm_connc(data->state.connc);
  }

  if ( ! (data->share && data->share->hostcache) ) {
    if ( !Curl_global_host_cache_use(data)) {
      Curl_hash_destroy(data->dns.hostcache);
    }
  }

  if(data->state.shared_conn) {
    /* this handle is still being used by a shared connection cache and thus
       we leave it around for now */
    Curl_multi_add_closure(data->state.shared_conn, data);

    return CURLE_OK;
  }

  /* Free the pathbuffer */
  Curl_safefree(data->reqdata.pathbuffer);
  Curl_safefree(data->reqdata.proto.generic);

  /* Close down all open SSL info and sessions */
  Curl_ssl_close_all(data);
  Curl_safefree(data->state.first_host);
  Curl_safefree(data->state.scratch);

  if(data->change.proxy_alloc)
    free(data->change.proxy);

  if(data->change.referer_alloc)
    free(data->change.referer);

  if(data->change.url_alloc)
    free(data->change.url);

  Curl_safefree(data->state.headerbuff);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  if(data->set.cookiejar) {
    if(data->change.cookielist) {
      /* If there is a list of cookie files to read, do it first so that
         we have all the told files read before we write the new jar */
      Curl_cookie_loadfiles(data);
    }

    /* we have a "destination" for all the cookies to get dumped to */
    if(Curl_cookie_output(data->cookies, data->set.cookiejar))
      infof(data, "WARNING: failed to save cookies in %s\n",
            data->set.cookiejar);
  }
  else {
    if(data->change.cookielist)
      /* since nothing is written, we can just free the list of cookie file
         names */
      curl_slist_free_all(data->change.cookielist); /* clean up list */
  }

  if( !data->share || (data->cookies != data->share->cookies) ) {
    Curl_cookie_cleanup(data->cookies);
  }
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
#endif

  Curl_digest_cleanup(data);

  Curl_safefree(data->info.contenttype);

  /* this destroys the channel and we cannot use it anymore after this */
  ares_destroy(data->state.areschannel);

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
  /* close iconv conversion descriptors */
  if (data->inbound_cd != (iconv_t)-1) {
     iconv_close(data->inbound_cd);
  }
  if (data->outbound_cd != (iconv_t)-1) {
     iconv_close(data->outbound_cd);
  }
  if (data->utf8_cd != (iconv_t)-1) {
     iconv_close(data->utf8_cd);
  }
#endif /* CURL_DOES_CONVERSIONS && HAVE_ICONV */

  /* No longer a dirty share, if it exists */
  if (data->share)
    data->share->dirty--;

  free(data);
  return CURLE_OK;
}

/* create a connection cache of a private or multi type */
struct conncache *Curl_mk_connc(int type)
{
  /* It is subject for debate how many default connections to have for a multi
     connection cache... */
  int default_amount = (type == CONNCACHE_PRIVATE)?5:10;
  struct conncache *c;

  c= calloc(sizeof(struct conncache), 1);
  if(!c)
    return NULL;

  c->connects = calloc(sizeof(struct connectdata *), default_amount);
  if(!c->connects) {
    free(c);
    return NULL;
  }

  c->num = default_amount;

  return c;
}

/* Free a connection cache. This is called from Curl_close() and
   curl_multi_cleanup(). */
void Curl_rm_connc(struct conncache *c)
{
  if(c->connects) {
    int i;
    for(i = 0; i < c->num; ++i)
      conn_free(c->connects[i]);

    free(c->connects);
  }

  free(c);
}

/**
 * Curl_open()
 *
 * @param curl is a pointer to a sessionhandle pointer that gets set by this
 * function.
 * @return CURLcode
 */

CURLcode Curl_open(struct SessionHandle **curl)
{
  CURLcode res = CURLE_OK;
  struct SessionHandle *data;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = (struct SessionHandle *)calloc(1, sizeof(struct SessionHandle));
  if(!data)
    /* this is a very serious error */
    return CURLE_OUT_OF_MEMORY;

  data->magic = CURLEASY_MAGIC_NUMBER;

#ifdef USE_ARES
  if(ARES_SUCCESS != ares_init(&data->state.areschannel)) {
    free(data);
    return CURLE_FAILED_INIT;
  }
  /* make sure that all other returns from this function should destroy the
     ares channel before returning error! */
#endif

  /* We do some initial setup here, all those fields that can't be just 0 */

  data->state.headerbuff=(char*)malloc(HEADERSIZE);
  if(!data->state.headerbuff)
    res = CURLE_OUT_OF_MEMORY;
  else {
    data->state.headersize=HEADERSIZE;

    data->set.out = stdout; /* default output to stdout */
    data->set.in  = stdin;  /* default input from stdin */
    data->set.err  = stderr;  /* default stderr to stderr */

    /* use fwrite as default function to store output */
    data->set.fwrite = (curl_write_callback)fwrite;

    /* use fread as default function to read input */
    data->set.fread = (curl_read_callback)fread;

    /* conversion callbacks for non-ASCII hosts */
    data->set.convfromnetwork = (curl_conv_callback)NULL;
    data->set.convtonetwork   = (curl_conv_callback)NULL;
    data->set.convfromutf8    = (curl_conv_callback)NULL;

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
    /* conversion descriptors for iconv calls */
    data->outbound_cd = (iconv_t)-1;
    data->inbound_cd  = (iconv_t)-1;
    data->utf8_cd     = (iconv_t)-1;
#endif /* CURL_DOES_CONVERSIONS && HAVE_ICONV */

    data->set.infilesize = -1; /* we don't know any size */
    data->set.postfieldsize = -1;
    data->set.maxredirs = -1; /* allow any amount by default */
    data->state.current_speed = -1; /* init to negative == impossible */

    data->set.httpreq = HTTPREQ_GET; /* Default HTTP request */
    data->set.ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
    data->set.ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */
    data->set.ftp_filemethod = FTPFILE_MULTICWD;
    data->set.dns_cache_timeout = 60; /* Timeout every 60 seconds by default */

    /* make libcurl quiet by default: */
    data->set.hide_progress = TRUE;  /* CURLOPT_NOPROGRESS changes these */
    data->progress.flags |= PGRS_HIDE;

    /* Set the default size of the SSL session ID cache */
    data->set.ssl.numsessions = 5;

    data->set.proxyport = 1080;
    data->set.proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */
    data->set.httpauth = CURLAUTH_BASIC;  /* defaults to basic */
    data->set.proxyauth = CURLAUTH_BASIC; /* defaults to basic */

    /* This no longer creates a connection cache here. It is instead made on
       the first call to curl_easy_perform() or when the handle is added to a
       multi stack. */

    /* most recent connection is not yet defined */
    data->state.lastconnect = -1;

    Curl_easy_initHandleData(data);

    /*
     * libcurl 7.10 introduced SSL verification *by default*! This needs to be
     * switched off unless wanted.
     */
    data->set.ssl.verifypeer = TRUE;
    data->set.ssl.verifyhost = 2;
#ifdef CURL_CA_BUNDLE
    /* This is our preferred CA cert bundle since install time */
    data->set.ssl.CAfile = (char *)CURL_CA_BUNDLE;
#endif
  }

  if(res) {
    ares_destroy(data->state.areschannel);
    if(data->state.headerbuff)
      free(data->state.headerbuff);
    free(data);
    data = NULL;
  }

  *curl = data;
  return CURLE_OK;
}

CURLcode Curl_setopt(struct SessionHandle *data, CURLoption option,
                     va_list param)
{
  char *argptr;
  CURLcode result = CURLE_OK;

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

      data->set.global_dns_cache = (bool)(0 != use_cache);
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
      long i;

      if(newconnects < data->state.connc->num) {
        /* Since this number is *decreased* from the existing number, we must
           close the possibly open connections that live on the indexes that
           are being removed!

           NOTE: for conncache_multi cases we must make sure that we only
           close handles not in use.
        */
        for(i=newconnects; i< data->state.connc->num; i++)
          Curl_disconnect(data->state.connc->connects[i]);

        /* If the most recent connection is no longer valid, mark it
           invalid. */
        if(data->state.lastconnect <= newconnects)
          data->state.lastconnect = -1;
      }
      if(newconnects > 0) {
        newptr= (struct connectdata **)
          realloc(data->state.connc->connects,
                  sizeof(struct connectdata *) * newconnects);
        if(!newptr)
          /* we closed a few connections in vain, but so what? */
          return CURLE_OUT_OF_MEMORY;

        /* nullify the newly added pointers */
        for(i=data->state.connc->num; i<newconnects; i++)
          newptr[i] = NULL;

        data->state.connc->connects = newptr;
        data->state.connc->num = newconnects;
      }
      /* we no longer support less than 1 as size for the connection cache,
         and I'm not sure it ever worked to set it to zero */
    }
    break;
  case CURLOPT_FORBID_REUSE:
    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    data->set.reuse_forbid = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_FRESH_CONNECT:
    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    data->set.reuse_fresh = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_VERBOSE:
    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    data->set.verbose = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_HEADER:
    /*
     * Set to include the header in the general data output stream.
     */
    data->set.include_header = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_NOPROGRESS:
    /*
     * Shut off the internal supported progress meter
     */
    data->set.hide_progress = (bool)(0 != va_arg(param, long));
    if(data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else
      data->progress.flags &= ~PGRS_HIDE;
    break;
  case CURLOPT_NOBODY:
    /*
     * Do not include the body part in the output data stream.
     */
    data->set.opt_no_body = (bool)(0 != va_arg(param, long));
    if(data->set.opt_no_body)
      /* in HTTP lingo, this means using the HEAD request */
      data->set.httpreq = HTTPREQ_HEAD;
    break;
  case CURLOPT_FAILONERROR:
    /*
     * Don't output the >=300 error code HTML-page, but instead only
     * return error.
     */
    data->set.http_fail_on_error = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_UPLOAD:
  case CURLOPT_PUT:
    /*
     * We want to sent data to the remote host. If this is HTTP, that equals
     * using the PUT request.
     */
    data->set.upload = (bool)(0 != va_arg(param, long));
    if(data->set.upload)
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->set.httpreq = HTTPREQ_PUT;
    break;
  case CURLOPT_FILETIME:
    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using curl_easy_getinfo().
     */
    data->set.get_filetime = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_FTP_CREATE_MISSING_DIRS:
    /*
     * An FTP option that modifies an upload to create missing directories on
     * the server.
     */
    data->set.ftp_create_missing_dirs = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_FTP_RESPONSE_TIMEOUT:
    /*
     * An FTP option that specifies how quickly an FTP response must be
     * obtained before it is considered failure.
     */
    data->set.ftp_response_timeout = va_arg( param , long );
    break;
  case CURLOPT_FTPLISTONLY:
    /*
     * An FTP option that changes the command to one that asks for a list
     * only, no file info details.
     */
    data->set.ftp_list_only = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_FTPAPPEND:
    /*
     * We want to upload and append to an existing (FTP) file.
     */
    data->set.ftp_append = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_FTP_FILEMETHOD:
    /*
     * How do access files over FTP.
     */
    data->set.ftp_filemethod = (curl_ftpfile)va_arg(param, long);
    break;
  case CURLOPT_NETRC:
    /*
     * Parse the $HOME/.netrc file
     */
    data->set.use_netrc = (enum CURL_NETRC_OPTION)va_arg(param, long);
    break;
  case CURLOPT_NETRC_FILE:
    /*
     * Use this file instead of the $HOME/.netrc file
     */
    data->set.netrc_file = va_arg(param, char *);
    break;
  case CURLOPT_TRANSFERTEXT:
    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    data->set.prefer_ascii = (bool)(0 != va_arg(param, long));
    break;
  case CURLOPT_TIMECONDITION:
    /*
     * Set HTTP time condition. This must be one of the defines in the
     * curl/curl.h header file.
     */
    data->set.timecondition = (curl_TimeCond)va_arg(param, long);
    break;
  case CURLOPT_TIMEVALUE:
    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)va_arg(param, long);
    break;
  case CURLOPT_SSLVERSION:
    /*
     * Set explicit SSL version to try to connect with, as some SSL
     * implementations are lame.
     */
    data->set.ssl.version = va_arg(param, long);
    break;

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_AUTOREFERER:
    /*
     * Switch on automatic referer that gets set if curl follows locations.
     */
    data->set.http_auto_referer = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_ENCODING:
    /*
     * String to use at the value of Accept-Encoding header.
     *
     * If the encoding is set to "" we use an Accept-Encoding header that
     * encompasses all the encodings we support.
     * If the encoding is set to NULL we don't send an Accept-Encoding header
     * and ignore an received Content-Encoding header.
     *
     */
    data->set.encoding = va_arg(param, char *);
    if(data->set.encoding && !*data->set.encoding)
      data->set.encoding = (char*)ALL_CONTENT_ENCODINGS;
    break;

  case CURLOPT_FOLLOWLOCATION:
    /*
     * Follow Location: header hints on a HTTP-server.
     */
    data->set.http_follow_location = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_UNRESTRICTED_AUTH:
    /*
     * Send authentication (user+password) when following locations, even when
     * hostname changed.
     */
    data->set.http_disable_hostname_check_before_authentication =
      (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_MAXREDIRS:
    /*
     * The maximum amount of hops you allow curl to follow Location:
     * headers. This should mostly be used to detect never-ending loops.
     */
    data->set.maxredirs = va_arg(param, long);
    break;

  case CURLOPT_POST:
    /* Does this option serve a purpose anymore? Yes it does, when
       CURLOPT_POSTFIELDS isn't used and the POST data is read off the
       callback! */
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_POST;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      data->set.httpreq = HTTPREQ_GET;
    break;

  case CURLOPT_POSTFIELDS:
    /*
     * A string with POST data. Makes curl HTTP POST. Even if it is NULL.
     */
    data->set.postfields = va_arg(param, char *);
    data->set.httpreq = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDSIZE:
    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    data->set.postfieldsize = va_arg(param, long);
    break;

  case CURLOPT_POSTFIELDSIZE_LARGE:
    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    data->set.postfieldsize = va_arg(param, curl_off_t);
    break;

  case CURLOPT_HTTPPOST:
    /*
     * Set to make us do HTTP POST
     */
    data->set.httppost = va_arg(param, struct curl_httppost *);
    data->set.httpreq = HTTPREQ_POST_FORM;
    data->set.opt_no_body = FALSE; /* this is implied */
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

  case CURLOPT_USERAGENT:
    /*
     * String to use in the HTTP User-Agent field
     */
    data->set.useragent = va_arg(param, char *);
    break;

  case CURLOPT_HTTPHEADER:
    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    data->set.headers = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_HTTP200ALIASES:
    /*
     * Set a list of aliases for HTTP 200 in response header
     */
    data->set.http200aliases = va_arg(param, struct curl_slist *);
    break;

#if !defined(CURL_DISABLE_COOKIES)
  case CURLOPT_COOKIE:
    /*
     * Cookie string to send to the remote server in the request.
     */
    data->set.cookie = va_arg(param, char *);
    break;

  case CURLOPT_COOKIEFILE:
    /*
     * Set cookie file to read and parse. Can be used multiple times.
     */
    argptr = (char *)va_arg(param, void *);
    if(argptr) {
      struct curl_slist *cl;
      /* append the cookie file name to the list of file names, and deal with
         them later */
      cl = curl_slist_append(data->change.cookielist, argptr);

      if(!cl)
        return CURLE_OUT_OF_MEMORY;

      data->change.cookielist = cl;
    }
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
    data->cookies = Curl_cookie_init(data, NULL, data->cookies,
                                     data->set.cookiesession);
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
    data->set.cookiesession = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_COOKIELIST:
    argptr = va_arg(param, char *);

    if(argptr == NULL)
      break;

    if(strequal(argptr, "ALL")) {
      /* clear all cookies */
      Curl_cookie_clearall(data->cookies);
      break;
    }
    else if(strequal(argptr, "SESS")) {
      /* clear session cookies */
      Curl_cookie_clearsess(data->cookies);
      break;
    }

    if(!data->cookies)
      /* if cookie engine was not running, activate it */
      data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);

    argptr = strdup(argptr);
    if(!argptr) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }

    if(checkprefix("Set-Cookie:", argptr))
      /* HTTP Header format line */
      Curl_cookie_add(data, data->cookies, TRUE, argptr + 11, NULL, NULL);

    else
      /* Netscape format line */
      Curl_cookie_add(data, data->cookies, FALSE, argptr, NULL, NULL);

    free(argptr);
    break;
#endif /* CURL_DISABLE_COOKIES */

  case CURLOPT_HTTPGET:
    /*
     * Set to force us do HTTP GET
     */
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_GET;
      data->set.upload = FALSE; /* switch off upload */
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    break;

  case CURLOPT_HTTP_VERSION:
    /*
     * This sets a requested HTTP version to be used. The value is one of
     * the listed enums in curl/curl.h.
     */
    data->set.httpversion = va_arg(param, long);
    break;

  case CURLOPT_HTTPPROXYTUNNEL:
    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    data->set.tunnel_thru_httpproxy = (bool)(0 != va_arg(param, long));
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

  case CURLOPT_PROXYPORT:
    /*
     * Explicitly set HTTP proxy port number.
     */
    data->set.proxyport = va_arg(param, long);
    break;

  case CURLOPT_HTTPAUTH:
    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    long auth = va_arg(param, long);
    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM; /* no NTLM without SSL */
#endif
#ifndef HAVE_GSSAPI
    auth &= ~CURLAUTH_GSSNEGOTIATE; /* no GSS-Negotiate without GSSAPI */
#endif
    if(!auth)
      return CURLE_FAILED_INIT; /* no supported types left! */

    data->set.httpauth = auth;
  }
  break;

  case CURLOPT_PROXYAUTH:
    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    long auth = va_arg(param, long);
    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM; /* no NTLM without SSL */
#endif
#ifndef HAVE_GSSAPI
    auth &= ~CURLAUTH_GSSNEGOTIATE; /* no GSS-Negotiate without GSSAPI */
#endif
    if(!auth)
      return CURLE_FAILED_INIT; /* no supported types left! */

    data->set.proxyauth = auth;
  }
  break;
#endif   /* CURL_DISABLE_HTTP */

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

  case CURLOPT_WRITEHEADER:
    /*
     * Custom pointer to pass the header write callback function
     */
    data->set.writeheader = (void *)va_arg(param, void *);
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

  case CURLOPT_FTP_USE_EPRT:
    data->set.ftp_use_eprt = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_FTP_USE_EPSV:
    data->set.ftp_use_epsv = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_FTP_SKIP_PASV_IP:
    /*
     * Enable or disable FTP_SKIP_PASV_IP, which will disable/enable the
     * bypass of the IP address in PASV responses.
     */
    data->set.ftp_skip_ip = (bool)(0 != va_arg(param, long));
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
  case CURLOPT_INFILESIZE_LARGE:
    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    data->set.infilesize = va_arg(param, curl_off_t);
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    /*
     * The low speed limit that if transfers are below this for
     * CURLOPT_LOW_SPEED_TIME, the transfer is aborted.
     */
    data->set.low_speed_limit=va_arg(param, long);
    break;
  case CURLOPT_MAX_SEND_SPEED_LARGE:
    /*
     * The max speed limit that sends transfer more than
     * CURLOPT_MAX_SEND_PER_SECOND bytes per second the transfer is
     * throttled..
     */
    data->set.max_send_speed=va_arg(param, curl_off_t);
    break;
  case CURLOPT_MAX_RECV_SPEED_LARGE:
    /*
     * The max speed limit that sends transfer more than
     * CURLOPT_MAX_RECV_PER_SECOND bytes per second the transfer is
     * throttled..
     */
    data->set.max_recv_speed=va_arg(param, curl_off_t);
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
    data->change.url_changed = TRUE;
    break;
  case CURLOPT_PORT:
    /*
     * The port number to use when getting the URL
     */
    data->set.use_port = va_arg(param, long);
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
  case CURLOPT_RESUME_FROM_LARGE:
    /*
     * Resume transfer at the give file position
     */
    data->set.set_resume_from = va_arg(param, curl_off_t);
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
    if(!data->set.fwrite)
      /* When set to NULL, reset to our internal default function */
      data->set.fwrite = (curl_write_callback)fwrite;
    break;
  case CURLOPT_READFUNCTION:
    /*
     * Read data callback
     */
    data->set.fread = va_arg(param, curl_read_callback);
    if(!data->set.fread)
      /* When set to NULL, reset to our internal default function */
      data->set.fread = (curl_read_callback)fread;
    break;
  case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
    /*
     * "Convert from network encoding" callback
     */
    data->set.convfromnetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_TO_NETWORK_FUNCTION:
    /*
     * "Convert to network encoding" callback
     */
    data->set.convtonetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_FROM_UTF8_FUNCTION:
    /*
     * "Convert from UTF-8 encoding" callback
     */
    data->set.convfromutf8 = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_IOCTLFUNCTION:
    /*
     * I/O control callback. Might be NULL.
     */
    data->set.ioctl = va_arg(param, curl_ioctl_callback);
    break;
  case CURLOPT_IOCTLDATA:
    /*
     * I/O control data pointer. Might be NULL.
     */
    data->set.ioctl_client = va_arg(param, void *);
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
    argptr = va_arg(param, char *);
    if (argptr && argptr[0])
       result = Curl_ssl_set_engine(data, argptr);
    break;

  case CURLOPT_SSLENGINE_DEFAULT:
    /*
     * flag to set engine as default.
     */
    result = Curl_ssl_set_engine_default(data);
    break;
  case CURLOPT_CRLF:
    /*
     * Kludgy option to enable CRLF conversions. Subject for removal.
     */
    data->set.crlf = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_INTERFACE:
    /*
     * Set what interface or address/hostname to bind the socket to when
     * performing an operation and thus what from-IP your connection will use.
     */
    data->set.device = va_arg(param, char *);
    break;
  case CURLOPT_LOCALPORT:
    /*
     * Set what local port to bind the socket to when performing an operation.
     */
    data->set.localport = (unsigned short) va_arg(param, long);
    break;
  case CURLOPT_LOCALPORTRANGE:
    /*
     * Set number of local ports to try, starting with CURLOPT_LOCALPORT.
     */
    data->set.localportrange = (int) va_arg(param, long);
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
  case CURLOPT_SSL_CTX_FUNCTION:
    /*
     * Set a SSL_CTX callback
     */
    data->set.ssl.fsslctx = va_arg(param, curl_ssl_ctx_callback);
    break;
  case CURLOPT_SSL_CTX_DATA:
    /*
     * Set a SSL_CTX callback parameter pointer
     */
    data->set.ssl.fsslctxp = va_arg(param, void *);
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

    if((data->set.buffer_size> (BUFSIZE -1 )) ||
       (data->set.buffer_size < 1))
      data->set.buffer_size = 0; /* huge internal default */

    break;

  case CURLOPT_NOSIGNAL:
    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    data->set.no_signal = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_SHARE:
    {
      struct Curl_share *set;
      set = va_arg(param, struct Curl_share *);

      /* disconnect from old share, if any */
      if(data->share) {
        Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

        if(data->dns.hostcachetype == HCACHE_SHARED) {
          data->dns.hostcache = NULL;
          data->dns.hostcachetype = HCACHE_NONE;
        }

        if(data->share->cookies == data->cookies)
          data->cookies = NULL;

        data->share->dirty--;

        Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
        data->share = NULL;
      }

      /* use new share if it set */
      data->share = set;
      if(data->share) {

        Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

        data->share->dirty++;

        if(data->share->hostcache) {
          /* use shared host cache, first free the private one if any */
          if(data->dns.hostcachetype == HCACHE_PRIVATE)
            Curl_hash_destroy(data->dns.hostcache);

          data->dns.hostcache = data->share->hostcache;
          data->dns.hostcachetype = HCACHE_SHARED;
        }
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
        if(data->share->cookies) {
          /* use shared cookie list, first free own one if any */
          if (data->cookies)
            Curl_cookie_cleanup(data->cookies);
          data->cookies = data->share->cookies;
        }
#endif   /* CURL_DISABLE_HTTP */
        Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);

      }
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      /* check cookie list is set */
      if(!data->cookies)
        data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE );
#endif   /* CURL_DISABLE_HTTP */
      /* check for host cache not needed,
       * it will be done by curl_easy_perform */
    }
    break;

  case CURLOPT_PROXYTYPE:
    /*
     * Set proxy type. HTTP/SOCKS4/SOCKS5
     */
    data->set.proxytype = (curl_proxytype)va_arg(param, long);
    break;

  case CURLOPT_PRIVATE:
    /*
     * Set private data pointer.
     */
    data->set.private_data = va_arg(param, char *);
    break;

  case CURLOPT_MAXFILESIZE:
    /*
     * Set the maximum size of a file to download.
     */
    data->set.max_filesize = va_arg(param, long);
    break;

  case CURLOPT_FTP_SSL:
    /*
     * Make FTP transfers attempt to use SSL/TLS.
     */
    data->set.ftp_ssl = (curl_ftpssl)va_arg(param, long);
    break;

  case CURLOPT_FTPSSLAUTH:
    /*
     * Set a specific auth for FTP-SSL transfers.
     */
    data->set.ftpsslauth = (curl_ftpauth)va_arg(param, long);
    break;

  case CURLOPT_IPRESOLVE:
    data->set.ip_version = va_arg(param, long);
    break;

  case CURLOPT_MAXFILESIZE_LARGE:
    /*
     * Set the maximum size of a file to download.
     */
    data->set.max_filesize = va_arg(param, curl_off_t);
    break;

  case CURLOPT_TCP_NODELAY:
    /*
     * Enable or disable TCP_NODELAY, which will disable/enable the Nagle
     * algorithm
     */
    data->set.tcp_nodelay = (bool)(0 != va_arg(param, long));
    break;

  /*********** 3rd party transfer options ***********/
  case CURLOPT_SOURCE_URL:
    /*
     * SOURCE URL
     */
    data->set.source_url = va_arg(param, char *);
    data->set.printhost = (data->set.source_url != NULL);
    break;

  case CURLOPT_SOURCE_USERPWD:
    /*
     * Use SOURCE USER[:PASSWORD]
     */
    data->set.source_userpwd = va_arg(param, char *);
    break;

  case CURLOPT_SOURCE_QUOTE:
    /*
     * List of RAW FTP commands to use after a connect
     */
    data->set.source_quote = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_SOURCE_PREQUOTE:
    /*
     * List of RAW FTP commands to use before a transfer on the source host
     */
    data->set.source_prequote = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_SOURCE_POSTQUOTE:
    /*
     * List of RAW FTP commands to use after a transfer on the source host
     */
    data->set.source_postquote = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_FTP_ACCOUNT:
    data->set.ftp_account = va_arg(param, char *);
    break;

  case CURLOPT_IGNORE_CONTENT_LENGTH:
    data->set.ignorecl = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_CONNECT_ONLY:
    /*
     * No data transfer, set up connection and let application use the socket
     */
    data->set.connect_only = (bool)(0 != va_arg(param, long));
    break;

  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
    data->set.ftp_alternative_to_user = va_arg(param, char *);
    break;

  case CURLOPT_SOCKOPTFUNCTION:
    /*
     * socket callback function: called after socket() but before connect()
     */
    data->set.fsockopt = va_arg(param, curl_sockopt_callback);
    break;

  case CURLOPT_SOCKOPTDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.sockopt_client = va_arg(param, void *);
    break;

  default:
    /* unknown tag and its companion, just ignore: */
    result = CURLE_FAILED_INIT; /* correct this */
    break;
  }

  return result;
}

static void conn_free(struct connectdata *conn)
{
  if (!conn)
    return;

  /* close possibly still open sockets */
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
    sclose(conn->sock[SECONDARYSOCKET]);
  if(CURL_SOCKET_BAD != conn->sock[FIRSTSOCKET])
    sclose(conn->sock[FIRSTSOCKET]);

  Curl_safefree(conn->user);
  Curl_safefree(conn->passwd);
  Curl_safefree(conn->proxyuser);
  Curl_safefree(conn->proxypasswd);
  Curl_safefree(conn->allocptr.proxyuserpwd);
  Curl_safefree(conn->allocptr.uagent);
  Curl_safefree(conn->allocptr.userpwd);
  Curl_safefree(conn->allocptr.accept_encoding);
  Curl_safefree(conn->allocptr.rangeline);
  Curl_safefree(conn->allocptr.ref);
  Curl_safefree(conn->allocptr.host);
  Curl_safefree(conn->allocptr.cookiehost);
  Curl_safefree(conn->ip_addr_str);
  Curl_safefree(conn->trailer);
  Curl_safefree(conn->sec_pathbuffer);
  Curl_safefree(conn->host.rawalloc); /* host name buffer */
  Curl_safefree(conn->proxy.rawalloc); /* proxy name buffer */

  Curl_llist_destroy(conn->send_pipe, NULL);
  Curl_llist_destroy(conn->recv_pipe, NULL);

  /* possible left-overs from the async name resolvers */
#if defined(USE_ARES)
  Curl_safefree(conn->async.hostname);
  Curl_safefree(conn->async.os_specific);
#elif defined(CURLRES_THREADED)
  Curl_destroy_thread_data(&conn->async);
#endif

  Curl_free_ssl_config(&conn->ssl_config);

  free(conn); /* free all the connection oriented data */
}

CURLcode Curl_disconnect(struct connectdata *conn)
{
  struct SessionHandle *data;
  if(!conn)
    return CURLE_OK; /* this is closed and fine already */
  data = conn->data;

#if defined(CURLDEBUG) && defined(AGGRESIVE_TEST)
  /* scan for DNS cache entries still marked as in use */
  Curl_hash_apply(data->hostcache,
                  NULL, Curl_scan_cache_used);
#endif

  Curl_expire(data, 0); /* shut off timers */
  Curl_hostcache_prune(data); /* kill old DNS cache entries */

  /*
   * The range string is usually freed in curl_done(), but we might
   * get here *instead* if we fail prematurely. Thus we need to be able
   * to free this resource here as well.
   */
  if(data->reqdata.rangestringalloc) {
    free(data->reqdata.range);
    data->reqdata.rangestringalloc = FALSE;
  }

  if((conn->ntlm.state != NTLMSTATE_NONE) ||
     (conn->proxyntlm.state != NTLMSTATE_NONE)) {
    /* Authentication data is a mix of connection-related and sessionhandle-
       related stuff. NTLM is connection-related so when we close the shop
       we shall forget. */
    data->state.authhost.done = FALSE;
    data->state.authhost.picked =
      data->state.authhost.want;

    data->state.authproxy.done = FALSE;
    data->state.authproxy.picked =
      data->state.authproxy.want;

    data->state.authproblem = FALSE;

    Curl_ntlm_cleanup(conn);
  }

  if(conn->curl_disconnect)
    /* This is set if protocol-specific cleanups should be made */
    conn->curl_disconnect(conn);

  if(-1 != conn->connectindex) {
    /* unlink ourselves! */
    infof(data, "Closing connection #%ld\n", conn->connectindex);
    data->state.connc->connects[conn->connectindex] = NULL;
  }

#ifdef USE_LIBIDN
  if(conn->host.encalloc)
    idn_free(conn->host.encalloc); /* encoded host name buffer, must be freed
                                      with idn_free() since this was allocated
                                      by libidn */
  if(conn->proxy.encalloc)
    idn_free(conn->proxy.encalloc); /* encoded proxy name buffer, must be
                                       freed with idn_free() since this was
                                       allocated by libidn */
#endif

  Curl_ssl_close(conn);

  /* Indicate to all handles on the pipe that we're dead */
  Curl_signalPipeClose(conn->send_pipe);
  Curl_signalPipeClose(conn->recv_pipe);

  conn_free(conn);

  return CURLE_OK;
}

/*
 * This function should return TRUE if the socket is to be assumed to
 * be dead. Most commonly this happens when the server has closed the
 * connection due to inactivity.
 */
static bool SocketIsDead(curl_socket_t sock)
{
  int sval;
  bool ret_val = TRUE;

  sval = Curl_select(sock, CURL_SOCKET_BAD, 0);
  if(sval == 0)
    /* timeout */
    ret_val = FALSE;

  return ret_val;
}

static bool IsPipeliningPossible(struct SessionHandle *handle)
{
  if (handle->multi && Curl_multi_canPipeline(handle->multi) &&
      (handle->set.httpreq == HTTPREQ_GET ||
       handle->set.httpreq == HTTPREQ_HEAD) &&
      handle->set.httpversion != CURL_HTTP_VERSION_1_0)
    return TRUE;

  return FALSE;
}

void Curl_addHandleToPipeline(struct SessionHandle *handle,
                              struct curl_llist *pipe)
{
  Curl_llist_insert_next(pipe,
                         pipe->tail,
                         handle);
}


void Curl_removeHandleFromPipeline(struct SessionHandle *handle,
                                   struct curl_llist *pipe)
{
  struct curl_llist_element *curr;

  curr = pipe->head;
  while (curr) {
    if (curr->ptr == handle) {
      Curl_llist_remove(pipe, curr, NULL);
      break;
    }
    curr = curr->next;
  }
}

#if 0
static void Curl_printPipeline(struct curl_llist *pipe)
{
  struct curl_llist_element *curr;

  curr = pipe->head;
  while (curr) {
    struct SessionHandle *data = (struct SessionHandle *) curr->ptr;
    infof(data, "Handle in pipeline: %s\n",
          data->reqdata.path);
    curr = curr->next;
  }
}
#endif

bool Curl_isHandleAtHead(struct SessionHandle *handle,
                         struct curl_llist *pipe)
{
  struct curl_llist_element *curr = pipe->head;
  if (curr) {
    return curr->ptr == handle ? TRUE : FALSE;
  }

  return FALSE;
}

void Curl_signalPipeClose(struct curl_llist *pipe)
{
  struct curl_llist_element *curr;

  curr = pipe->head;
  while (curr) {
    struct curl_llist_element *next = curr->next;
    struct SessionHandle *data = (struct SessionHandle *) curr->ptr;

    data->state.pipe_broke = TRUE;

    Curl_llist_remove(pipe, curr, NULL);
    curr = next;
  }
}


/*
 * Given one filled in connection struct (named needle), this function should
 * detect if there already is one that has all the significant details
 * exactly the same and thus should be used instead.
 *
 * If there is a match, this function returns TRUE - and has marked the
 * connection as 'in-use'. It must later be called with ConnectionDone() to
 * return back to 'idle' (unused) state.
 */
static bool
ConnectionExists(struct SessionHandle *data,
                 struct connectdata *needle,
                 struct connectdata **usethis)
{
  long i;
  struct connectdata *check;
  bool canPipeline = IsPipeliningPossible(data);

  for(i=0; i< data->state.connc->num; i++) {
    bool match = FALSE;
    /*
     * Note that if we use a HTTP proxy, we check connections to that
     * proxy and not to the actual remote server.
     */
    check = data->state.connc->connects[i];
    if(!check)
      /* NULL pointer means not filled-in entry */
      continue;

    if(check->inuse && !canPipeline)
      /* can only happen within multi handles, and means that another easy
         handle is using this connection */
      continue;

    if (check->send_pipe->size >= MAX_PIPELINE_LENGTH ||
        check->recv_pipe->size >= MAX_PIPELINE_LENGTH)
      continue;

    if((needle->protocol&PROT_SSL) != (check->protocol&PROT_SSL))
      /* don't do mixed SSL and non-SSL connections */
      continue;

    if(!needle->bits.httpproxy || needle->protocol&PROT_SSL) {
      /* The requested connection does not use a HTTP proxy or it
         uses SSL. */

      if(!(needle->protocol&PROT_SSL) && check->bits.httpproxy)
        /* we don't do SSL but the cached connection has a proxy,
           then don't match this */
        continue;

      if(strequal(needle->protostr, check->protostr) &&
         strequal(needle->host.name, check->host.name) &&
         (needle->remote_port == check->remote_port) ) {
        if(needle->protocol & PROT_SSL) {
          /* This is SSL, verify that we're using the same
             ssl options as well */
          if(!Curl_ssl_config_matches(&needle->ssl_config,
                                      &check->ssl_config)) {
            continue;
          }
        }
        if((needle->protocol & PROT_FTP) ||
           ((needle->protocol & PROT_HTTP) &&
            (data->state.authhost.want==CURLAUTH_NTLM))) {
          /* This is FTP or HTTP+NTLM, verify that we're using the same name
             and password as well */
          if(!strequal(needle->user, check->user) ||
             !strequal(needle->passwd, check->passwd)) {
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
         strequal(needle->proxy.name, check->proxy.name) &&
         needle->port == check->port) {
        /* This is the same proxy connection, use it! */
        match = TRUE;
      }
    }

    if(match) {
      bool dead = SocketIsDead(check->sock[FIRSTSOCKET]);
      if(dead) {
        /*
         */
        check->data = data;
        infof(data, "Connection %d seems to be dead!\n", i);
        Curl_disconnect(check); /* disconnect resources */
        data->state.connc->connects[i]=NULL; /* nothing here */

        /* There's no need to continue searching, because we only store
           one connection for each unique set of identifiers */
        return FALSE;
      }

      check->inuse = TRUE; /* mark this as being in use so that no other
                              handle in a multi stack may nick it */

      if (canPipeline) {
          /* Mark the connection as being in a pipeline */
          check->is_in_pipeline = TRUE;
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
static long
ConnectionKillOne(struct SessionHandle *data)
{
  long i;
  struct connectdata *conn;
  long highscore=-1;
  long connindex=-1;
  long score;
  struct timeval now;

  now = Curl_tvnow();

  for(i=0; data->state.connc && (i< data->state.connc->num); i++) {
    conn = data->state.connc->connects[i];

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
    /* Set the connection's owner correctly */
    conn = data->state.connc->connects[connindex];
    conn->data = data;

    /* the winner gets the honour of being disconnected */
    (void)Curl_disconnect(conn);

    /* clean the array entry */
    data->state.connc->connects[connindex] = NULL;
  }

  return connindex; /* return the available index or -1 */
}

/* this connection can now be marked 'idle' */
static void
ConnectionDone(struct connectdata *conn)
{
  conn->inuse = FALSE;
  conn->data = NULL;

  if (conn->send_pipe == 0 &&
      conn->recv_pipe == 0)
      conn->is_in_pipeline = FALSE;
}

/*
 * The given input connection struct pointer is to be stored. If the "cache"
 * is already full, we must clean out the most suitable using the previously
 * set policy.
 *
 * The given connection should be unique. That must've been checked prior to
 * this call.
 */
static long
ConnectionStore(struct SessionHandle *data,
                struct connectdata *conn)
{
  long i;
  for(i=0; i< data->state.connc->num; i++) {
    if(!data->state.connc->connects[i])
      break;
  }
  if(i == data->state.connc->num) {
    /* there was no room available, kill one */
    i = ConnectionKillOne(data);
    infof(data, "Connection (#%d) was killed to make room\n", i);
  }

  conn->connectindex = i; /* Make the child know where the pointer to this
                             particular data is stored. But note that this -1
                             if this is not within the cache and this is
                             probably not checked for everywhere (yet). */
  conn->inuse = TRUE;
  if(-1 != i) {
    /* Only do this if a true index was returned, if -1 was returned there
       is no room in the cache for an unknown reason and we cannot store
       this there.

       TODO: make sure we really can work with more handles than positions in
       the cache, or possibly we should (allow to automatically) resize the
       connection cache when we add more easy handles to a multi handle!
    */
    data->state.connc->connects[i] = conn; /* fill in this */
    conn->data = data;
  }

  return i;
}

/*
* This function logs in to a SOCKS4 proxy and sends the specifics to the final
* destination server.
*
* Reference :
*   http://socks.permeo.com/protocol/socks4.protocol
*
* Note :
*   Nonsupport "SOCKS 4A (Simple Extension to SOCKS 4 Protocol)"
*   Nonsupport "Identification Protocol (RFC1413)"
*/
static int handleSock4Proxy(const char *proxy_name,
                            struct SessionHandle *data,
                            struct connectdata *conn)
{
  unsigned char socksreq[262]; /* room for SOCKS4 request incl. user id */
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];

  Curl_nonblock(sock, FALSE);

  /*
  * Compose socks4 request
  *
  * Request format
  *
  *     +----+----+----+----+----+----+----+----+----+----+....+----+
  *     | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
  *     +----+----+----+----+----+----+----+----+----+----+....+----+
  * # of bytes:  1    1      2              4           variable       1
  */

  socksreq[0] = 4; /* version (SOCKS4) */
  socksreq[1] = 1; /* connect */
  *((unsigned short*)&socksreq[2]) = htons(conn->remote_port);

  /* DNS resolve */
  {
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    int rc;

    rc = Curl_resolv(conn, conn->host.name, (int)conn->remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return 1;

    if(rc == CURLRESOLV_PENDING)
      /* this requires that we're in "wait for resolve" state */
      rc = Curl_wait_for_resolv(conn, &dns);

    /*
    * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
    * returns a Curl_addrinfo pointer that may not always look the same.
    */
    if(dns)
      hp=dns->addr;
    if (hp) {
      char buf[64];
      unsigned short ip[4];
      Curl_printable_address(hp, buf, sizeof(buf));

      if(4 == sscanf( buf, "%hu.%hu.%hu.%hu",
        &ip[0], &ip[1], &ip[2], &ip[3])) {
          /* Set DSTIP */
          socksreq[4] = (unsigned char)ip[0];
          socksreq[5] = (unsigned char)ip[1];
          socksreq[6] = (unsigned char)ip[2];
          socksreq[7] = (unsigned char)ip[3];
        }
      else
        hp = NULL; /* fail! */

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */

    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
        conn->host.name);
      return 1;
    }
  }

  /*
   * This is currently not supporting "Identification Protocol (RFC1413)".
   */
  socksreq[8] = 0; /* ensure empty userid is NUL-terminated */
  if (proxy_name)
    strlcat((char*)socksreq + 8, proxy_name, sizeof(socksreq) - 8);

  /*
   * Make connection
   */
  {
    ssize_t actualread;
    ssize_t written;
    int packetsize = 9 +
      (int)strlen((char*)socksreq + 8); /* size including NUL */

    /* Send request */
    code = Curl_write(conn, sock, (char *)socksreq, packetsize, &written);
    if ((code != CURLE_OK) || (written != packetsize)) {
      failf(data, "Failed to send SOCKS4 connect request.");
      return 1;
    }

    packetsize = 8; /* receive data size */

    /* Receive response */
    result = Curl_read(conn, sock, (char *)socksreq, packetsize, &actualread);
    if ((result != CURLE_OK) || (actualread != packetsize)) {
      failf(data, "Failed to receive SOCKS4 connect request ack.");
      return 1;
    }

    /*
    * Response format
    *
    *     +----+----+----+----+----+----+----+----+
    *     | VN | CD | DSTPORT |      DSTIP        |
    *     +----+----+----+----+----+----+----+----+
    * # of bytes:  1    1      2              4
    *
    * VN is the version of the reply code and should be 0. CD is the result
    * code with one of the following values:
    *
    * 90: request granted
    * 91: request rejected or failed
    * 92: request rejected because SOCKS server cannot connect to
    *     identd on the client
    * 93: request rejected because the client program and identd
    *     report different user-ids
    */

    /* wrong version ? */
    if (socksreq[0] != 0) {
      failf(data,
        "SOCKS4 reply has wrong version, version should be 4.");
      return 1;
    }

    /* Result */
    switch(socksreq[1])
    {
      case 90:
        infof(data, "SOCKS4 request granted.\n");
        break;
      case 91:
        failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected or failed.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
          socksreq[1]);
        return 1;
      case 92:
        failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
          socksreq[1]);
        return 1;
      case 93:
        failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
          socksreq[1]);
        return 1;
      default :
        failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", Unknown.",
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

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
static int handleSock5Proxy(const char *proxy_name,
                            const char *proxy_password,
                            struct connectdata *conn)
{
  /*
    According to the RFC1928, section "6.  Replies". This is what a SOCK5
    replies:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

    Where:

    o  VER    protocol version: X'05'
    o  REP    Reply field:
    o  X'00' succeeded
  */

  unsigned char socksreq[600]; /* room for large user/pw (255 max each) */
  ssize_t actualread;
  ssize_t written;
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data = conn->data;
  long timeout;

  /* get timeout */
  if(data->set.timeout && data->set.connecttimeout) {
    if (data->set.timeout < data->set.connecttimeout)
      timeout = data->set.timeout*1000;
    else
      timeout = data->set.connecttimeout*1000;
  }
  else if(data->set.timeout)
    timeout = data->set.timeout*1000;
  else if(data->set.connecttimeout)
    timeout = data->set.connecttimeout*1000;
  else
    timeout = DEFAULT_CONNECT_TIMEOUT;

  Curl_nonblock(sock, TRUE);

  /* wait until socket gets connected */
  result = Curl_select(CURL_SOCKET_BAD, sock, (int)timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5: no connection here");
    return 1;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5: connection timeout");
    return 1;
  }

  if(result & CSELECT_ERR) {
    failf(conn->data, "SOCKS5: error occured during connection");
    return 1;
  }

  socksreq[0] = 5; /* version */
  socksreq[1] = (char)(proxy_name ? 2 : 1); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 2; /* username/password */

  Curl_nonblock(sock, FALSE);

  code = Curl_write(conn, sock, (char *)socksreq, (2 + (int)socksreq[1]),
                      &written);
  if ((code != CURLE_OK) || (written != (2 + (int)socksreq[1]))) {
    failf(data, "Unable to send initial SOCKS5 request.");
    return 1;
  }

  Curl_nonblock(sock, TRUE);

  result = Curl_select(sock, CURL_SOCKET_BAD, (int)timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5 nothing to read");
    return 1;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5 read timeout");
    return 1;
  }

  if(result & CSELECT_ERR) {
    failf(conn->data, "SOCKS5 read error occured");
    return 1;
  }

  Curl_nonblock(sock, FALSE);

  result=Curl_read(conn, sock, (char *)socksreq, 2, &actualread);
  if ((result != CURLE_OK) || (actualread != 2)) {
    failf(data, "Unable to receive initial SOCKS5 response.");
    return 1;
  }

  if (socksreq[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return 1;
  }
  if (socksreq[1] == 0) {
    /* Nothing to do, no authentication needed */
    ;
  }
  else if (socksreq[1] == 2) {
    /* Needs user name and password */
    size_t userlen, pwlen;
    int len;
    if(proxy_name && proxy_password) {
      userlen = strlen(proxy_name);
      pwlen = proxy_password?strlen(proxy_password):0;
    }
    else {
      userlen = 0;
      pwlen = 0;
    }

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

    code = Curl_write(conn, sock, (char *)socksreq, len, &written);
    if ((code != CURLE_OK) || (len != written)) {
      failf(data, "Failed to send SOCKS5 sub-negotiation request.");
      return 1;
    }

    result=Curl_read(conn, sock, (char *)socksreq, 2, &actualread);
    if ((result != CURLE_OK) || (actualread != 2)) {
      failf(data, "Unable to receive SOCKS5 sub-negotiation response.");
      return 1;
    }

    /* ignore the first (VER) byte */
    if (socksreq[1] != 0) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return 1;
    }

    /* Everything is good so far, user was authenticated! */
  }
  else {
    /* error */
    if (socksreq[1] == 1) {
      failf(data,
            "SOCKS5 GSSAPI per-message authentication is not supported.");
      return 1;
    }
    else if (socksreq[1] == 255) {
      if (!proxy_name || !*proxy_name) {
        failf(data,
              "No authentication method was acceptable. (It is quite likely"
              " that the SOCKS5 server wanted a username/password, since none"
              " was supplied to the server on this connection.)");
      }
      else {
        failf(data, "No authentication method was acceptable.");
      }
      return 1;
    }
    else {
      failf(data,
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
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    int rc = Curl_resolv(conn, conn->host.name, (int)conn->remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return 1;

    if(rc == CURLRESOLV_PENDING)
      /* this requires that we're in "wait for resolve" state */
      rc = Curl_wait_for_resolv(conn, &dns);

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if (hp) {
      char buf[64];
      unsigned short ip[4];
      Curl_printable_address(hp, buf, sizeof(buf));

      if(4 == sscanf( buf, "%hu.%hu.%hu.%hu",
                      &ip[0], &ip[1], &ip[2], &ip[3])) {
        socksreq[4] = (unsigned char)ip[0];
        socksreq[5] = (unsigned char)ip[1];
        socksreq[6] = (unsigned char)ip[2];
        socksreq[7] = (unsigned char)ip[3];
      }
      else
        hp = NULL; /* fail! */

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */
    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            conn->host.name);
      return 1;
    }
  }

  *((unsigned short*)&socksreq[8]) = htons(conn->remote_port);

  {
    const int packetsize = 10;

    code = Curl_write(conn, sock, (char *)socksreq, packetsize, &written);
    if ((code != CURLE_OK) || (written != packetsize)) {
      failf(data, "Failed to send SOCKS5 connect request.");
      return 1;
    }

    result = Curl_read(conn, sock, (char *)socksreq, packetsize, &actualread);
    if ((result != CURLE_OK) || (actualread != packetsize)) {
      failf(data, "Failed to receive SOCKS5 connect request ack.");
      return 1;
    }

    if (socksreq[0] != 5) { /* version */
      failf(data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return 1;
    }
    if (socksreq[1] != 0) { /* Anything besides 0 is an error */
        failf(data,
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

static CURLcode ConnectPlease(struct SessionHandle *data,
                              struct connectdata *conn,
                              struct Curl_dns_entry *hostaddr,
                              bool *connected)
{
  CURLcode result;
  Curl_addrinfo *addr;
  char *hostname = data->change.proxy?conn->proxy.name:conn->host.name;

  infof(data, "About to connect() to %s%s port %d\n",
        data->change.proxy?"proxy ":"",
        hostname, conn->port);

  /*************************************************************
   * Connect to server/proxy
   *************************************************************/
  result= Curl_connecthost(conn,
                           hostaddr,
                           &conn->sock[FIRSTSOCKET],
                           &addr,
                           connected);
  if(CURLE_OK == result) {
    /* All is cool, then we store the current information */
    conn->dns_entry = hostaddr;
    conn->ip_addr = addr;

    Curl_store_ip_addr(conn);

    switch(data->set.proxytype) {
    case CURLPROXY_SOCKS5:
      return handleSock5Proxy(conn->proxyuser,
                              conn->proxypasswd,
                              conn) ?
        CURLE_COULDNT_CONNECT : CURLE_OK;
    case CURLPROXY_HTTP:
      /* do nothing here. handled later. */
      break;
    case CURLPROXY_SOCKS4:
      return handleSock4Proxy(conn->proxyuser, data, conn) ?
        CURLE_COULDNT_CONNECT : CURLE_OK;
    default:
      failf(data, "unknown proxytype option given");
      return CURLE_COULDNT_CONNECT;
    }
  }

  return result;
}

/*
 * verboseconnect() displays verbose information after a connect
 */
static void verboseconnect(struct connectdata *conn)
{
  infof(conn->data, "Connected to %s (%s) port %d\n",
        conn->bits.httpproxy ? conn->proxy.dispname : conn->host.dispname,
        conn->ip_addr_str, conn->port);
}

int Curl_protocol_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks)
{
  if(conn->curl_proto_getsock)
    return conn->curl_proto_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

int Curl_doing_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks)
{
  if(conn && conn->curl_doing_getsock)
    return conn->curl_doing_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

/*
 * We are doing protocol-specific connecting and this is being called over and
 * over from the multi interface until the connection phase is done on
 * protocol layer.
 */

CURLcode Curl_protocol_connecting(struct connectdata *conn,
                                  bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->curl_connecting) {
    *done = FALSE;
    result = conn->curl_connecting(conn, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We are DOING this is being called over and over from the multi interface
 * until the DOING phase is done on protocol layer.
 */

CURLcode Curl_protocol_doing(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->curl_doing) {
    *done = FALSE;
    result = conn->curl_doing(conn, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We have discovered that the TCP connection has been successful, we can now
 * proceed with some action.
 *
 */
CURLcode Curl_protocol_connect(struct connectdata *conn,
                               bool *protocol_done)
{
  CURLcode result=CURLE_OK;
  struct SessionHandle *data = conn->data;

  *protocol_done = FALSE;

  if(conn->bits.tcpconnect && conn->bits.protoconnstart) {
    /* We already are connected, get back. This may happen when the connect
       worked fine in the first call, like when we connect to a local server
       or proxy. Note that we don't know if the protocol is actually done.

       Unless this protocol doesn't have any protocol-connect callback, as
       then we know we're done. */
    if(!conn->curl_connecting)
      *protocol_done = TRUE;

    return CURLE_OK;
  }

  if(!conn->bits.tcpconnect) {

    Curl_pgrsTime(data, TIMER_CONNECT); /* connect done */

    if(data->set.verbose)
      verboseconnect(conn);
  }

  if(!conn->bits.protoconnstart) {
    if(conn->curl_connect) {
      /* is there a protocol-specific connect() procedure? */

      /* Set start time here for timeout purposes in the connect procedure, it
         is later set again for the progress meter purpose */
      conn->now = Curl_tvnow();

      /* Call the protocol-specific connect function */
      result = conn->curl_connect(conn, protocol_done);
    }
    else
      *protocol_done = TRUE;

    /* it has started, possibly even completed but that knowledge isn't stored
       in this bit! */
    conn->bits.protoconnstart = TRUE;
  }

  return result; /* pass back status */
}

/*
 * Helpers for IDNA convertions.
 */
#ifdef USE_LIBIDN
static bool is_ASCII_name(const char *hostname)
{
  const unsigned char *ch = (const unsigned char*)hostname;

  while (*ch) {
    if (*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}

/*
 * Check if characters in hostname is allowed in Top Level Domain.
 */
static bool tld_check_name(struct SessionHandle *data,
                           const char *ace_hostname)
{
  size_t err_pos;
  char *uc_name = NULL;
  int rc;

  /* Convert (and downcase) ACE-name back into locale's character set */
  rc = idna_to_unicode_lzlz(ace_hostname, &uc_name, 0);
  if (rc != IDNA_SUCCESS)
    return (FALSE);

  rc = tld_check_lz(uc_name, &err_pos, NULL);
  if (rc == TLD_INVALID)
     infof(data, "WARNING: %s; pos %u = `%c'/0x%02X\n",
#ifdef HAVE_TLD_STRERROR
           tld_strerror((Tld_rc)rc),
#else
           "<no msg>",
#endif
           err_pos, uc_name[err_pos],
           uc_name[err_pos] & 255);
  else if (rc != TLD_SUCCESS)
       infof(data, "WARNING: TLD check for %s failed; %s\n",
             uc_name,
#ifdef HAVE_TLD_STRERROR
             tld_strerror((Tld_rc)rc)
#else
             "<no msg>"
#endif
         );
  if (uc_name)
     idn_free(uc_name);
  return (bool)(rc == TLD_SUCCESS);
}
#endif

static void fix_hostname(struct SessionHandle *data,
                         struct connectdata *conn, struct hostname *host)
{
  /* set the name we use to display the host name */
  host->dispname = host->name;

#ifdef USE_LIBIDN
  /*************************************************************
   * Check name for non-ASCII and convert hostname to ACE form.
   *************************************************************/
  if (!is_ASCII_name(host->name) &&
      stringprep_check_version(LIBIDN_REQUIRED_VERSION)) {
    char *ace_hostname = NULL;
    int rc = idna_to_ascii_lz(host->name, &ace_hostname, 0);
    infof (data, "Input domain encoded as `%s'\n",
           stringprep_locale_charset ());
    if (rc != IDNA_SUCCESS)
      infof(data, "Failed to convert %s to ACE; %s\n",
            host->name, Curl_idn_strerror(conn,rc));
    else {
      /* tld_check_name() displays a warning if the host name contains
         "illegal" characters for this TLD */
      (void)tld_check_name(data, ace_hostname);

      host->encalloc = ace_hostname;
      /* change the name pointer to point to the encoded hostname */
      host->name = host->encalloc;
    }
  }
#else
  (void)data; /* never used */
  (void)conn; /* never used */
#endif
}

/*
 * Parse URL and fill in the relevant members of the connection struct.
 */
static CURLcode ParseURLAndFillConnection(struct SessionHandle *data,
                                          struct connectdata *conn)
{
  char *at;
  char *tmp;

  char *path = data->reqdata.path;

  /*************************************************************
   * Parse the URL.
   *
   * We need to parse the url even when using the proxy, because we will need
   * the hostname and port in case we are trying to SSL connect through the
   * proxy -- and we don't know if we will need to use SSL until we parse the
   * url ...
   ************************************************************/
  if((2 == sscanf(data->change.url, "%15[^:]:%[^\n]",
                  conn->protostr,
                  path)) && strequal(conn->protostr, "file")) {
    if(path[0] == '/' && path[1] == '/') {
      /* Allow omitted hostname (e.g. file:/<path>).  This is not strictly
       * speaking a valid file: URL by RFC 1738, but treating file:/<path> as
       * file://localhost/<path> is similar to how other schemes treat missing
       * hostnames.  See RFC 1808. */

      /* This cannot be done with strcpy() in a portable manner, since the
         memory areas overlap! */
      memmove(path, path + 2, strlen(path + 2)+1);
    }
    /*
     * we deal with file://<host>/<path> differently since it supports no
     * hostname other than "localhost" and "127.0.0.1", which is unique among
     * the URL protocols specified in RFC 1738
     */
    if(path[0] != '/') {
      /* the URL included a host name, we ignore host names in file:// URLs
         as the standards don't define what to do with them */
      char *ptr=strchr(path, '/');
      if(ptr) {
        /* there was a slash present

           RFC1738 (section 3.1, page 5) says:

           The rest of the locator consists of data specific to the scheme,
           and is known as the "url-path". It supplies the details of how the
           specified resource can be accessed. Note that the "/" between the
           host (or port) and the url-path is NOT part of the url-path.

           As most agents use file://localhost/foo to get '/foo' although the
           slash preceding foo is a separator and not a slash for the path,
           a URL as file://localhost//foo must be valid as well, to refer to
           the same file with an absolute path.
        */

        if(ptr[1] && ('/' == ptr[1]))
          /* if there was two slashes, we skip the first one as that is then
             used truly as a separator */
          ptr++;

        /* This cannot be made with strcpy, as the memory chunks overlap! */
        memmove(path, ptr, strlen(ptr)+1);
      }
    }

    strcpy(conn->protostr, "file"); /* store protocol string lowercase */
  }
  else {
    /* clear path */
    path[0]=0;

    if (2 > sscanf(data->change.url,
                   "%15[^\n:]://%[^\n/]%[^\n]",
                   conn->protostr,
                   conn->host.name, path)) {

      /*
       * The URL was badly formatted, let's try the browser-style _without_
       * protocol specified like 'http://'.
       */
      if((1 > sscanf(data->change.url, "%[^\n/]%[^\n]",
                     conn->host.name, path)) ) {
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

      if(checkprefix("FTP.", conn->host.name))
        strcpy(conn->protostr, "ftp");
#ifdef USE_SSL
      else if(checkprefix("FTPS", conn->host.name))
        strcpy(conn->protostr, "ftps");
#endif /* USE_SSL */
      else if(checkprefix("TELNET.", conn->host.name))
        strcpy(conn->protostr, "telnet");
      else if (checkprefix("DICT.", conn->host.name))
        strcpy(conn->protostr, "DICT");
      else if (checkprefix("LDAP.", conn->host.name))
        strcpy(conn->protostr, "LDAP");
      else {
        strcpy(conn->protostr, "http");
      }

      conn->protocol |= PROT_MISSING; /* not given in URL */
    }
  }

  /* We search for '?' in the host name (but only on the right side of a
   * @-letter to allow ?-letters in username and password) to handle things
   * like http://example.com?param= (notice the missing '/').
   */
  at = strchr(conn->host.name, '@');
  if(at)
    tmp = strchr(at+1, '?');
  else
    tmp = strchr(conn->host.name, '?');

  if(tmp) {
    /* We must insert a slash before the '?'-letter in the URL. If the URL had
       a slash after the '?', that is where the path currently begins and the
       '?string' is still part of the host name.

       We must move the trailing part from the host name and put it first in
       the path. And have it all prefixed with a slash.
    */

    size_t hostlen = strlen(tmp);
    size_t pathlen = strlen(path);

    /* move the existing path plus the zero byte forward, to make room for
       the host-name part */
    memmove(path+hostlen+1, path, pathlen+1);

     /* now copy the trailing host part in front of the existing path */
    memcpy(path+1, tmp, hostlen);

    path[0]='/'; /* prepend the missing slash */

    *tmp=0; /* now cut off the hostname at the ? */
  }
  else if(!path[0]) {
    /* if there's no path set, use a single slash */
    strcpy(path, "/");
  }

  /* If the URL is malformatted (missing a '/' after hostname before path) we
   * insert a slash here. The only letter except '/' we accept to start a path
   * is '?'.
   */
  if(path[0] == '?') {
    /* We need this function to deal with overlapping memory areas. We know
       that the memory area 'path' points to is 'urllen' bytes big and that
       is bigger than the path. Use +1 to move the zero byte too. */
    memmove(&path[1], path, strlen(path)+1);
    path[0] = '/';
  }

  /*
   * So if the URL was A://B/C,
   *   conn->protostr is A
   *   conn->host.name is B
   *   data->reqdata.path is /C
   */

  return CURLE_OK;
}

static void llist_dtor(void *user, void *element)
{
  (void)user;
  (void)element;
  /* Do nothing */
}


/**
 * CreateConnection() sets up a new connectdata struct, or re-uses an already
 * existing one, and resolves host name.
 *
 * if this function returns CURLE_OK and *async is set to TRUE, the resolve
 * response will be coming asynchronously. If *async is FALSE, the name is
 * already resolved.
 *
 * @param data The sessionhandle pointer
 * @param in_connect is set to the next connection data pointer
 * @param addr is set to the new dns entry for this connection. If this
 *        connection is re-used it will be NULL.
 * @param async is set TRUE/FALSE depending on the nature of this lookup
 * @return CURLcode
 * @see SetupConnection()
 *
 * *NOTE* this function assigns the conn->data pointer!
 */

static CURLcode CreateConnection(struct SessionHandle *data,
                                 struct connectdata **in_connect,
                                 struct Curl_dns_entry **addr,
                                 bool *async)
{

  char *tmp;
  CURLcode result=CURLE_OK;
  struct connectdata *conn;
  struct connectdata *conn_temp = NULL;
  size_t urllen;
  struct Curl_dns_entry *hostaddr;
#if defined(HAVE_ALARM) && !defined(USE_ARES)
  unsigned int prev_alarm=0;
#endif
  char endbracket;
  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  int rc;
  bool reuse;

#ifndef USE_ARES
#ifdef SIGALRM
#ifdef HAVE_SIGACTION
  struct sigaction keep_sigact;   /* store the old struct here */
  bool keep_copysig=FALSE;        /* did copy it? */
#else
#ifdef HAVE_SIGNAL
  void (*keep_sigact)(int);       /* store the old handler here */
#endif /* HAVE_SIGNAL */
#endif /* HAVE_SIGACTION */
#endif /* SIGALRM */
#endif /* USE_ARES */

  *addr = NULL; /* nothing yet */
  *async = FALSE;

  /*************************************************************
   * Check input data
   *************************************************************/

  if(!data->change.url)
    return CURLE_URL_MALFORMAT;

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */

  conn = (struct connectdata *)calloc(sizeof(struct connectdata), 1);
  if(!conn) {
    *in_connect = NULL; /* clear the pointer */
    return CURLE_OUT_OF_MEMORY;
  }
  /* We must set the return variable as soon as possible, so that our
     parent can cleanup any possible allocs we may have done before
     any failure */
  *in_connect = conn;

  /* and we setup a few fields in case we end up actually using this struct */

  conn->data = data; /* Setup the association between this connection
                        and the SessionHandle */

  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     /* no file descriptor */
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->connectindex = -1;    /* no index */
  conn->bits.httpproxy = (data->change.proxy && *data->change.proxy &&
                          (data->set.proxytype == CURLPROXY_HTTP))?
    TRUE:FALSE; /* http proxy or not */

  /* Default protocol-independent behavior doesn't support persistent
     connections, so we set this to force-close. Protocols that support
     this need to set this to FALSE in their "curl_do" functions. */
  conn->bits.close = TRUE;

  conn->readchannel_inuse = FALSE;
  conn->writechannel_inuse = FALSE;

  /* Initialize the pipeline lists */
  conn->send_pipe = Curl_llist_alloc((curl_llist_dtor) llist_dtor);
  conn->recv_pipe = Curl_llist_alloc((curl_llist_dtor) llist_dtor);

  /* Store creation time to help future close decision making */
  conn->created = Curl_tvnow();

  data->reqdata.use_range = data->set.set_range?TRUE:FALSE; /* range status */

  data->reqdata.range = data->set.set_range; /* clone the range setting */
  data->reqdata.resume_from = data->set.set_resume_from;

  conn->bits.user_passwd = data->set.userpwd?1:0;
  conn->bits.proxy_user_passwd = data->set.proxyuserpwd?1:0;
  conn->bits.no_body = data->set.opt_no_body;
  conn->bits.tunnel_proxy = data->set.tunnel_thru_httpproxy;
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;

  /* This initing continues below, see the comment "Continue connectdata
   * initialization here" */

  /***********************************************************
   * We need to allocate memory to store the path in. We get the size of the
   * full URL to be sure, and we need to make it at least 256 bytes since
   * other parts of the code will rely on this fact
   ***********************************************************/
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->change.url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;

  if (!data->set.source_url /* 3rd party FTP */
      && data->reqdata.pathbuffer) {
      /* Free the old buffer */
      free(data->reqdata.pathbuffer);
  }

  /*
   * We malloc() the buffers below urllen+2 to make room for to possibilities:
   * 1 - an extra terminating zero
   * 2 - an extra slash (in case a syntax like "www.host.com?moo" is used)
   */

  data->reqdata.pathbuffer=(char *)malloc(urllen+2);
  if(NULL == data->reqdata.pathbuffer)
    return CURLE_OUT_OF_MEMORY; /* really bad error */
  data->reqdata.path = data->reqdata.pathbuffer;

  conn->host.rawalloc=(char *)malloc(urllen+2);
  if(NULL == conn->host.rawalloc)
    return CURLE_OUT_OF_MEMORY;

  conn->host.name = conn->host.rawalloc;
  conn->host.name[0] = 0;

  result = ParseURLAndFillConnection(data, conn);
  if (result != CURLE_OK) {
      return result;
  }

  /*************************************************************
   * Take care of proxy authentication stuff
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    char proxyuser[MAX_CURL_USER_LENGTH]="";
    char proxypasswd[MAX_CURL_PASSWORD_LENGTH]="";

    sscanf(data->set.proxyuserpwd,
           "%" MAX_CURL_USER_LENGTH_TXT "[^:]:"
           "%" MAX_CURL_PASSWORD_LENGTH_TXT "[^\n]",
           proxyuser, proxypasswd);

    conn->proxyuser = curl_easy_unescape(data, proxyuser, 0, NULL);
    if(!conn->proxyuser)
      return CURLE_OUT_OF_MEMORY;

    conn->proxypasswd = curl_easy_unescape(data, proxypasswd, 0, NULL);
    if(!conn->proxypasswd)
      return CURLE_OUT_OF_MEMORY;
  }

#ifndef CURL_DISABLE_HTTP
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
        size_t namelen;
        char *endptr = strchr(conn->host.name, ':');
        if(endptr)
          namelen=endptr-conn->host.name;
        else
          namelen=strlen(conn->host.name);

        if(strlen(nope) <= namelen) {
          char *checkn=
            conn->host.name + namelen - strlen(nope);
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
          *envp++ = (char)tolower((int)*protop++);

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
            *envp = (char)toupper((int)*envp);
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
          long bits = conn->protocol & (PROT_HTTPS|PROT_SSL);
          data->change.proxy = proxy;
          data->change.proxy_alloc=TRUE; /* this needs to be freed later */
          conn->bits.httpproxy = TRUE;

          /* force this to become HTTP */
          conn->protocol = PROT_HTTP | bits;
        }
      } /* if (!nope) - it wasn't specified non-proxy */
    } /* NO_PROXY wasn't specified or '*' */
    if(no_proxy)
      free(no_proxy);
  } /* if not using proxy */
#endif /* CURL_DISABLE_HTTP */

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
  if(data->reqdata.resume_from) {
    if(!data->reqdata.use_range) {
      /* if it already was in use, we just skip this */
      data->reqdata.range = aprintf("%" FORMAT_OFF_T "-", data->reqdata.resume_from);
      if(!data->reqdata.range)
        return CURLE_OUT_OF_MEMORY;
      data->reqdata.rangestringalloc = TRUE; /* mark as allocated */
      data->reqdata.use_range = 1; /* switch on range usage */
    }
  }
#endif
  /*************************************************************
   * Setup internals depending on protocol
   *************************************************************/

  conn->socktype = SOCK_STREAM; /* most of them are TCP streams */

  if (strequal(conn->protostr, "HTTP")) {
#ifndef CURL_DISABLE_HTTP
    conn->port = PORT_HTTP;
    conn->remote_port = PORT_HTTP;
    conn->protocol |= PROT_HTTP;
    conn->curl_do = Curl_http;
    conn->curl_do_more = (Curl_do_more_func)NULL;
    conn->curl_done = Curl_http_done;
    conn->curl_connect = Curl_http_connect;
#else
    failf(data, LIBCURL_NAME
          " was built with HTTP disabled, http: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }
  else if (strequal(conn->protostr, "HTTPS")) {
#if defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)

    conn->port = PORT_HTTPS;
    conn->remote_port = PORT_HTTPS;
    conn->protocol |= PROT_HTTP|PROT_HTTPS|PROT_SSL;

    conn->curl_do = Curl_http;
    conn->curl_do_more = (Curl_do_more_func)NULL;
    conn->curl_done = Curl_http_done;
    conn->curl_connect = Curl_http_connect;
    conn->curl_connecting = Curl_https_connecting;
    conn->curl_proto_getsock = Curl_https_getsock;

#else /* USE_SS */
    failf(data, LIBCURL_NAME
          " was built with SSL disabled, https: not supported!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSL */
  }
  else if(strequal(conn->protostr, "FTP") ||
          strequal(conn->protostr, "FTPS")) {

#ifndef CURL_DISABLE_FTP
    char *type;
    int port = PORT_FTP;

    if(strequal(conn->protostr, "FTPS")) {
#ifdef USE_SSL
      conn->protocol |= PROT_FTPS|PROT_SSL;
      conn->ssl[SECONDARYSOCKET].use = TRUE; /* send data securely */
      port = PORT_FTPS;
#else
      failf(data, LIBCURL_NAME
            " was built with SSL disabled, ftps: not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSL */
    }

    conn->port = port;
    conn->remote_port = (unsigned short)port;
    conn->protocol |= PROT_FTP|PROT_CLOSEACTION;

    if(data->change.proxy &&
       *data->change.proxy &&
       !data->set.tunnel_thru_httpproxy) {
      /* Unless we have asked to tunnel ftp operations through the proxy, we
         switch and use HTTP operations only */
#ifndef CURL_DISABLE_HTTP
      conn->curl_do = Curl_http;
      conn->curl_done = Curl_http_done;
      conn->protocol = PROT_HTTP; /* switch to HTTP */
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
      conn->curl_connecting = Curl_ftp_multi_statemach;
      conn->curl_doing = Curl_ftp_doing;
      conn->curl_proto_getsock = Curl_ftp_getsock;
      conn->curl_doing_getsock = Curl_ftp_getsock;
      conn->curl_disconnect = Curl_ftp_disconnect;
    }

    data->reqdata.path++; /* don't include the initial slash */

    /* FTP URLs support an extension like ";type=<typecode>" that
     * we'll try to get now! */
    type=strstr(data->reqdata.path, ";type=");
    if(!type) {
      type=strstr(conn->host.rawalloc, ";type=");
    }
    if(type) {
      char command;
      *type=0;                     /* it was in the middle of the hostname */
      command = (char)toupper((int)type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
        data->set.prefer_ascii = TRUE;
        break;
      case 'D': /* directory mode */
        data->set.ftp_list_only = TRUE;
        break;
      case 'I': /* binary mode */
      default:
        /* switch off ASCII */
        data->set.prefer_ascii = FALSE;
        break;
      }
    }
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

    conn->port = PORT_TELNET;
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
    conn->port = PORT_DICT;
    conn->remote_port = PORT_DICT;
    conn->curl_do = Curl_dict;
    conn->curl_done = (Curl_done_func)NULL; /* no DICT-specific done */
#else
    failf(data, LIBCURL_NAME
          " was built with DICT disabled!");
#endif
  }
  else if (strequal(conn->protostr, "LDAP")) {
#ifndef CURL_DISABLE_LDAP
    conn->protocol |= PROT_LDAP;
    conn->port = PORT_LDAP;
    conn->remote_port = PORT_LDAP;
    conn->curl_do = Curl_ldap;
    conn->curl_done = (Curl_done_func)NULL; /* no LDAP-specific done */
#else
    failf(data, LIBCURL_NAME
          " was built with LDAP disabled!");
#endif
  }
  else if (strequal(conn->protostr, "FILE")) {
#ifndef CURL_DISABLE_FILE
    conn->protocol |= PROT_FILE;

    conn->curl_do = Curl_file;
    conn->curl_done = Curl_file_done;

    /* anyway, this is supposed to be the connect function so we better
       at least check that the file is present here! */
    result = Curl_file_connect(conn);

    /* Setup a "faked" transfer that'll do nothing */
    if(CURLE_OK == result) {
      conn->bits.tcpconnect = TRUE; /* we are "connected */
      result = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, /* no download */
                                   -1, NULL); /* no upload */
    }

    return result;
#else
    failf(data, LIBCURL_NAME
          " was built with FILE disabled!");
#endif
  }
  else if (strequal(conn->protostr, "TFTP")) {
#ifndef CURL_DISABLE_TFTP
    char *type;
    conn->socktype = SOCK_DGRAM; /* UDP datagram based */
    conn->protocol |= PROT_TFTP;
    conn->port = PORT_TFTP;
    conn->remote_port = PORT_TFTP;
    conn->curl_connect = Curl_tftp_connect;
    conn->curl_do = Curl_tftp;
    conn->curl_done = Curl_tftp_done;
    /* TFTP URLs support an extension like ";mode=<typecode>" that
     * we'll try to get now! */
    type=strstr(data->reqdata.path, ";mode=");
    if(!type) {
      type=strstr(conn->host.rawalloc, ";mode=");
    }
    if(type) {
      char command;
      *type=0;                     /* it was in the middle of the hostname */
      command = (char)toupper((int)type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
      case 'N': /* NETASCII mode */
        data->set.prefer_ascii = TRUE;
        break;
      case 'O': /* octet mode */
      case 'I': /* binary mode */
      default:
        /* switch off ASCII */
        data->set.prefer_ascii = FALSE;
        break;
      }
    }
#else
    failf(data, LIBCURL_NAME
          " was built with TFTP disabled!");
#endif
  }
  else {
    /* We fell through all checks and thus we don't support the specified
       protocol */
    failf(data, "Unsupported protocol: %s", conn->protostr);
    return CURLE_UNSUPPORTED_PROTOCOL;
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
    char *portptr;
    char *atsign;

    if(NULL == proxydup) {
      failf(data, "memory shortage");
      return CURLE_OUT_OF_MEMORY;
    }

    /* We do the proxy host string parsing here. We want the host name and the
     * port name. Accept a protocol:// prefix, even though it should just be
     * ignored.
     */

    /* Skip the protocol part if present */
    endofprot=strstr(proxyptr, "://");
    if(endofprot)
      proxyptr = endofprot+3;

    /* Is there a username and password given in this proxy url? */
    atsign = strchr(proxyptr, '@');
    if(atsign) {
      char proxyuser[MAX_CURL_USER_LENGTH];
      char proxypasswd[MAX_CURL_PASSWORD_LENGTH];

      if(2 == sscanf(proxyptr,
                     "%" MAX_CURL_USER_LENGTH_TXT"[^:]:"
                     "%" MAX_CURL_PASSWORD_LENGTH_TXT "[^@]",
                     proxyuser, proxypasswd)) {
        CURLcode res = CURLE_OK;

        /* found user and password, rip them out.  note that we are
           unescaping them, as there is otherwise no way to have a
           username or password with reserved characters like ':' in
           them. */
        Curl_safefree(conn->proxyuser);
        conn->proxyuser = curl_easy_unescape(data, proxyuser, 0, NULL);

        if(!conn->proxyuser)
          res = CURLE_OUT_OF_MEMORY;
        else {
          Curl_safefree(conn->proxypasswd);
          conn->proxypasswd = curl_easy_unescape(data, proxypasswd, 0, NULL);

          if(!conn->proxypasswd)
            res = CURLE_OUT_OF_MEMORY;
        }

        if(CURLE_OK == res) {
          conn->bits.proxy_user_passwd = TRUE; /* enable it */
          atsign = strdup(atsign+1); /* the right side of the @-letter */

          if(atsign) {
            free(proxydup); /* free the former proxy string */
            proxydup = proxyptr = atsign; /* now use this instead */
          }
          else
            res = CURLE_OUT_OF_MEMORY;
        }

        if(res) {
          free(proxydup); /* free the allocated proxy string */
          return res;
        }
      }
    }

    /* start scanning for port number at this point */
    portptr = proxyptr;

    /* detect and extract RFC2732-style IPv6-addresses */
    if(*proxyptr == '[') {
      char *ptr = ++proxyptr; /* advance beyond the initial bracket */
      while(*ptr && (isxdigit((int)*ptr) || (*ptr == ':')))
        ptr++;
      if(*ptr == ']') {
        /* yeps, it ended nicely with a bracket as well */
        *ptr = 0;
        portptr = ptr+1;
      }
      /* Note that if this didn't end with a bracket, we still advanced the
       * proxyptr first, but I can't see anything wrong with that as no host
       * name nor a numeric can legally start with a bracket.
       */
    }

    /* Get port number off proxy.server.com:1080 */
    prox_portno = strchr(portptr, ':');
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
    conn->proxy.rawalloc = strdup(proxyptr);
    conn->proxy.name = conn->proxy.rawalloc;

    free(proxydup); /* free the duplicate pointer and not the modified */
    if(!conn->proxy.rawalloc)
      return CURLE_OUT_OF_MEMORY;
  }

  /*************************************************************
   * If the protcol is using SSL and HTTP proxy is used, we set
   * the tunnel_proxy bit.
   *************************************************************/
  if((conn->protocol&PROT_SSL) && conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  /*************************************************************
   * Take care of user and password authentication stuff
   *************************************************************/

  /*
   * Inputs: data->set.userpwd   (CURLOPT_USERPWD)
   *         data->set.fpasswd   (CURLOPT_PASSWDFUNCTION)
   *         data->set.use_netrc (CURLOPT_NETRC)
   *         conn->host.name
   *         netrc file
   *         hard-coded defaults
   *
   * Outputs: (almost :- all currently undefined)
   *          conn->bits.user_passwd  - non-zero if non-default passwords exist
   *          conn->user              - non-zero length if defined
   *          conn->passwd            -   ditto
   *          conn->host.name          - remove user name and password
   */

  /* At this point, we're hoping all the other special cases have
   * been taken care of, so conn->host.name is at most
   *    [user[:password]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */

  user[0] =0;   /* to make everything well-defined */
  passwd[0]=0;

  if (conn->protocol & (PROT_FTP|PROT_HTTP)) {
    /* This is a FTP or HTTP URL, we will now try to extract the possible
     * user+password pair in a string like:
     * ftp://user:password@ftp.my.site:8021/README */
    char *ptr=strchr(conn->host.name, '@');
    char *userpass = conn->host.name;
    if(ptr != NULL) {
      /* there's a user+password given here, to the left of the @ */

      conn->host.name = ++ptr;

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
          sscanf(userpass, "%" MAX_CURL_USER_LENGTH_TXT "[^:@]:"
                 "%" MAX_CURL_PASSWORD_LENGTH_TXT "[^@]",
                 user, passwd);
        }
        else
          /* no name given, get the password only */
          sscanf(userpass, ":%" MAX_CURL_PASSWORD_LENGTH_TXT "[^@]", passwd);

        if(user[0]) {
          char *newname=curl_easy_unescape(data, user, 0, NULL);
          if(!newname)
            return CURLE_OUT_OF_MEMORY;
          if(strlen(newname) < sizeof(user))
            strcpy(user, newname);

          /* if the new name is longer than accepted, then just use
             the unconverted name, it'll be wrong but what the heck */
          free(newname);
        }
        if (passwd[0]) {
          /* we have a password found in the URL, decode it! */
          char *newpasswd=curl_easy_unescape(data, passwd, 0, NULL);
          if(!newpasswd)
            return CURLE_OUT_OF_MEMORY;
          if(strlen(newpasswd) < sizeof(passwd))
            strcpy(passwd, newpasswd);

          free(newpasswd);
        }
      }
    }
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
   * The conn->host.name is currently [user:passwd@]host[:port] where host
   * could be a hostname, IPv4 address or IPv6 address.
   *************************************************************/
  if((1 == sscanf(conn->host.name, "[%*39[0-9a-fA-F:.]%c", &endbracket)) &&
     (']' == endbracket)) {
    /* this is a RFC2732-style specified IP-address */
    conn->bits.ipv6_ip = TRUE;

    conn->host.name++; /* pass the starting bracket */
    tmp = strchr(conn->host.name, ']');
    *tmp = 0; /* zero terminate */
    tmp++; /* pass the ending bracket */
    if(':' != *tmp)
      tmp = NULL; /* no port number available */
  }
  else
    tmp = strrchr(conn->host.name, ':');

  if(data->set.use_port && data->state.allow_port) {
    /* if set, we use this and ignore the port possibly given in the URL */
    conn->remote_port = (unsigned short)data->set.use_port;
    if(tmp)
      *tmp = '\0'; /* cut off the name there anyway - if there was a port
                      number - since the port number is to be ignored! */
    if(conn->bits.httpproxy) {
      /* we need to create new URL with the new port number */
      char *url;

      url = aprintf("http://%s:%d%s", conn->host.name, conn->remote_port,
                    data->reqdata.path);
      if(!url)
        return CURLE_OUT_OF_MEMORY;

      if(data->change.url_alloc)
        free(data->change.url);

      data->change.url = url;
      data->change.url_alloc = TRUE;
    }
  }
  else if (tmp) {
    /* no CURLOPT_PORT given, extract the one from the URL */

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

  /* Programmatically set password:
   *   - always applies, if available
   *   - takes precedence over the values we just set above
   * so scribble it over the top.
   * User-supplied passwords are assumed not to need unescaping.
   *
   * user_password is set in "inherit initial knowledge' above,
   * so it doesn't have to be set in this block
   */
  if (data->set.userpwd != NULL) {
    /* the name is given, get user+password */
    sscanf(data->set.userpwd,
           "%" MAX_CURL_USER_LENGTH_TXT "[^:]:"
           "%" MAX_CURL_PASSWORD_LENGTH_TXT "[^\n]",
           user, passwd);
  }

  conn->bits.netrc = FALSE;
  if (data->set.use_netrc != CURL_NETRC_IGNORED) {
    if(Curl_parsenetrc(conn->host.name,
                       user, passwd,
                       data->set.netrc_file)) {
      infof(data, "Couldn't find host %s in the " DOT_CHAR
            "netrc file, using defaults\n",
            conn->host.name);
    }
    else {
      /* set bits.netrc TRUE to remember that we got the name from a .netrc
         file, so that it is safe to use even if we followed a Location: to a
         different host or similar. */
      conn->bits.netrc = TRUE;

      conn->bits.user_passwd = 1; /* enable user+password */
    }
  }

  /* If our protocol needs a password and we have none, use the defaults */
  if ( (conn->protocol & PROT_FTP) &&
       !conn->bits.user_passwd) {

    conn->user = strdup(CURL_DEFAULT_USER);
    conn->passwd = strdup(CURL_DEFAULT_PASSWORD);
    /* This is the default password, so DON'T set conn->bits.user_passwd */
  }
  else {
    /* store user + password, zero-length if not set */
    conn->user = strdup(user);
    conn->passwd = strdup(passwd);
  }
  if(!conn->user || !conn->passwd)
    return CURLE_OUT_OF_MEMORY;

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  /* get a cloned copy of the SSL config situation stored in the
     connection struct */
  if(!Curl_clone_ssl_config(&data->set.ssl, &conn->ssl_config))
    return CURLE_OUT_OF_MEMORY;

  /* reuse_fresh is TRUE if we are told to use a new connection by force, but
     we only acknowledge this option if this is not a re-used connection
     already (which happens due to follow-location or during a HTTP
     authentication phase). */
  if(data->set.reuse_fresh && !data->state.this_is_a_follow)
    reuse = FALSE;
  else
    reuse = ConnectionExists(data, conn, &conn_temp);

  if(reuse) {
    /*
     * We already have a connection for this, we got the former connection
     * in the conn_temp variable and thus we need to cleanup the one we
     * just allocated before we can move along and use the previously
     * existing one.
     */
    struct connectdata *old_conn = conn;

    if(old_conn->proxy.rawalloc)
      free(old_conn->proxy.rawalloc);

    /* free the SSL config struct from this connection struct as this was
       allocated in vain and is targeted for destruction */
    Curl_free_ssl_config(&conn->ssl_config);

    conn = conn_temp;        /* use this connection from now on */

    conn->data = old_conn->data;

    /* get the user+password information from the old_conn struct since it may
     * be new for this request even when we re-use an existing connection */
    conn->bits.user_passwd = old_conn->bits.user_passwd;
    if (conn->bits.user_passwd) {
      /* use the new user namd and password though */
      Curl_safefree(conn->user);
      Curl_safefree(conn->passwd);
      conn->user = old_conn->user;
      conn->passwd = old_conn->passwd;
      old_conn->user = NULL;
      old_conn->passwd = NULL;
    }

    conn->bits.proxy_user_passwd = old_conn->bits.proxy_user_passwd;
    if (conn->bits.proxy_user_passwd) {
      /* use the new proxy user name and proxy password though */
      Curl_safefree(conn->proxyuser);
      Curl_safefree(conn->proxypasswd);
      conn->proxyuser = old_conn->proxyuser;
      conn->proxypasswd = old_conn->proxypasswd;
      old_conn->proxyuser = NULL;
      old_conn->proxypasswd = NULL;
    }

    /* host can change, when doing keepalive with a proxy ! */
    if (conn->bits.httpproxy) {
      free(conn->host.rawalloc);
      conn->host=old_conn->host;
    }

    /* get the newly set value, not the old one */
    conn->bits.no_body = old_conn->bits.no_body;

    if (!conn->bits.httpproxy)
      free(old_conn->host.rawalloc); /* free the newly allocated name buffer */

    /* re-use init */
    conn->bits.reuse = TRUE; /* yes, we're re-using here */
    conn->bits.chunk = FALSE; /* always assume not chunked unless told
                                 otherwise */

    Curl_safefree(old_conn->user);
    Curl_safefree(old_conn->passwd);
    Curl_safefree(old_conn->proxyuser);
    Curl_safefree(old_conn->proxypasswd);
    Curl_llist_destroy(old_conn->send_pipe, NULL);
    Curl_llist_destroy(old_conn->recv_pipe, NULL);

    free(old_conn);          /* we don't need this anymore */

    /*
     * If we're doing a resumed transfer, we need to setup our stuff
     * properly.
     */
    data->reqdata.resume_from = data->set.set_resume_from;
    if (data->reqdata.resume_from) {
      if (data->reqdata.rangestringalloc == TRUE)
        free(data->reqdata.range);
      data->reqdata.range = aprintf("%" FORMAT_OFF_T "-",
                                    data->reqdata.resume_from);
      if(!data->reqdata.range)
        return CURLE_OUT_OF_MEMORY;

      /* tell ourselves to fetch this range */
      data->reqdata.use_range = TRUE;        /* enable range download */
      data->reqdata.rangestringalloc = TRUE; /* mark range string allocated */
    }
    else if (data->set.set_range) {
      /* There is a range, but is not a resume, useful for random ftp access */
      data->reqdata.range = strdup(data->set.set_range);
      if(!data->reqdata.range)
        return CURLE_OUT_OF_MEMORY;
      data->reqdata.rangestringalloc = TRUE; /* mark range string allocated */
      data->reqdata.use_range = TRUE;        /* enable range download */
    }
    else
      data->reqdata.use_range = FALSE; /* disable range download */

    *in_connect = conn;      /* return this instead! */

    infof(data, "Re-using existing connection! (#%ld) with host %s\n",
          conn->connectindex,
          conn->bits.httpproxy?conn->proxy.dispname:conn->host.dispname);
  }
  else {
    /*
     * This is a brand new connection, so let's store it in the connection
     * cache of ours!
     */
    ConnectionStore(data, conn);
  }

  /* Continue connectdata initialization here. */

  /*
   *
   * Inherit the proper values from the urldata struct AFTER we have arranged
   * the persistent connection stuff */
  conn->fread = data->set.fread;
  conn->fread_in = data->set.in;

  conn->bits.upload_chunky =
    ((conn->protocol&PROT_HTTP) &&
     data->set.upload &&
     (data->set.infilesize == -1) &&
     (data->set.httpversion != CURL_HTTP_VERSION_1_0))?
    /* HTTP, upload, unknown file size and not HTTP 1.0 */
    TRUE:
  /* else, no chunky upload */
  FALSE;

#ifndef USE_ARES
  /*************************************************************
   * Set timeout if that is being used, and we're not using an asynchronous
   * name resolve.
   *************************************************************/
  if((data->set.timeout || data->set.connecttimeout) && !data->set.no_signal) {
    /*************************************************************
     * Set signal handler to catch SIGALRM
     * Store the old value to be able to set it back later!
     *************************************************************/

#ifdef SIGALRM
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
#else /* HAVE_SIGACTION */
    /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
    keep_sigact = signal(SIGALRM, alarmfunc);
#endif
#endif /* HAVE_SIGACTION */

    /* We set the timeout on the name resolving phase first, separately from
     * the download/upload part to allow a maximum time on everything. This is
     * a signal-based timeout, why it won't work and shouldn't be used in
     * multi-threaded environments. */

#ifdef HAVE_ALARM
    /* alarm() makes a signal get sent when the timeout fires off, and that
       will abort system calls */
    prev_alarm = alarm((unsigned int) (data->set.connecttimeout?
                                       data->set.connecttimeout:
                                       data->set.timeout));
    /* We can expect the conn->created time to be "now", as that was just
       recently set in the beginning of this function and nothing slow
       has been done since then until now. */
#endif
#endif /* SIGALRM */
  }
#endif /* USE_ARES */

  /*************************************************************
   * Resolve the name of the server or proxy
   *************************************************************/
  if(conn->bits.reuse) {
    /* re-used connection, no resolving is necessary */
    hostaddr = NULL;
    /* we'll need to clear conn->dns_entry later in Curl_disconnect() */

    if (conn->bits.httpproxy)
      fix_hostname(data, conn, &conn->host);
  }
  else {
    /* this is a fresh connect */

    /* set a pointer to the hostname we display */
    fix_hostname(data, conn, &conn->host);

    if(!data->change.proxy || !*data->change.proxy) {
      /* If not connecting via a proxy, extract the port from the URL, if it is
       * there, thus overriding any defaults that might have been set above. */
      conn->port =  conn->remote_port; /* it is the same port */

      /* Resolve target host right on */
      rc = Curl_resolv(conn, conn->host.name, (int)conn->port, &hostaddr);
      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve host '%s'", conn->host.dispname);
        result =  CURLE_COULDNT_RESOLVE_HOST;
        /* don't return yet, we need to clean up the timeout first */
      }
    }
    else {
      /* This is a proxy that hasn't been resolved yet. */

      /* IDN-fix the proxy name */
      fix_hostname(data, conn, &conn->proxy);

      /* resolve proxy */
      rc = Curl_resolv(conn, conn->proxy.name, (int)conn->port, &hostaddr);

      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve proxy '%s'", conn->proxy.dispname);
        result = CURLE_COULDNT_RESOLVE_PROXY;
        /* don't return yet, we need to clean up the timeout first */
      }
    }
  }
  *addr = hostaddr;

#if defined(HAVE_ALARM) && defined(SIGALRM) && !defined(USE_ARES)
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
#endif /* HAVE_SIGACTION */

    /* switch back the alarm() to either zero or to what it was before minus
       the time we spent until now! */
    if(prev_alarm) {
      /* there was an alarm() set before us, now put it back */
      unsigned long elapsed_ms = Curl_tvdiff(Curl_tvnow(), conn->created);
      unsigned long alarm_set;

      /* the alarm period is counted in even number of seconds */
      alarm_set = prev_alarm - elapsed_ms/1000;

      if(!alarm_set ||
         ((alarm_set >= 0x80000000) && (prev_alarm < 0x80000000)) ) {
        /* if the alarm time-left reached zero or turned "negative" (counted
           with unsigned values), we should fire off a SIGALRM here, but we
           won't, and zero would be to switch it off so we never set it to
           less than 1! */
        alarm(1);
        result = CURLE_OPERATION_TIMEOUTED;
        failf(data, "Previous alarm fired off!");
      }
      else
        alarm((unsigned int)alarm_set);
    }
    else
      alarm(0); /* just shut it off */
  }
#endif

  return result;
}

/* SetupConnection() is called after the name resolve initiated in
 * CreateConnection() is all done.
 *
 * NOTE: the argument 'hostaddr' is NULL when this function is called for a
 * re-used connection.
 *
 * conn->data MUST already have been setup fine (in CreateConnection)
 */

static CURLcode SetupConnection(struct connectdata *conn,
                                struct Curl_dns_entry *hostaddr,
                                bool *protocol_done)
{
  CURLcode result=CURLE_OK;
  struct SessionHandle *data = conn->data;

  Curl_pgrsTime(data, TIMER_NAMELOOKUP);

  if(conn->protocol & PROT_FILE) {
    /* There's nothing in this function to setup if we're only doing
       a file:// transfer */
    *protocol_done = TRUE;
    return result;
  }
  *protocol_done = FALSE; /* default to not done */

  /*************************************************************
   * Send user-agent to HTTP proxies even if the target protocol
   * isn't HTTP.
   *************************************************************/
  if((conn->protocol&PROT_HTTP) ||
     (data->change.proxy && *data->change.proxy)) {
    if(data->set.useragent) {
      Curl_safefree(conn->allocptr.uagent);
      conn->allocptr.uagent =
        aprintf("User-Agent: %s\015\012", data->set.useragent);
      if(!conn->allocptr.uagent)
        return CURLE_OUT_OF_MEMORY;
    }
  }

#ifdef CURL_DO_LINEEND_CONV
  data->state.crlf_conversions = 0; /* reset CRLF conversion counter */
#endif /* CURL_DO_LINEEND_CONV */

  if(CURL_SOCKET_BAD == conn->sock[FIRSTSOCKET]) {
    bool connected = FALSE;

    /* Connect only if not already connected! */
    result = ConnectPlease(data, conn, hostaddr, &connected);

    if(connected) {
      result = Curl_protocol_connect(conn, protocol_done);
      if(CURLE_OK == result)
        conn->bits.tcpconnect = TRUE;
    }
    else
      conn->bits.tcpconnect = FALSE;


    if(CURLE_OK != result)
      return result;
  }
  else {
    Curl_pgrsTime(data, TIMER_CONNECT); /* we're connected already */
    conn->bits.tcpconnect = TRUE;
    *protocol_done = TRUE;
    if(data->set.verbose)
      verboseconnect(conn);
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
                      struct connectdata **in_connect,
                      bool *asyncp,
                      bool *protocol_done)
{
  CURLcode code;
  struct Curl_dns_entry *dns;

  *asyncp = FALSE; /* assume synchronous resolves by default */

  /* call the stuff that needs to be called */
  code = CreateConnection(data, in_connect, &dns, asyncp);

  if(CURLE_OK == code) {
    /* no error */
    if(dns || !*asyncp)
      /* If an address is available it means that we already have the name
         resolved, OR it isn't async. if this is a re-used connection 'dns'
         will be NULL here. Continue connecting from here */
      code = SetupConnection(*in_connect, dns, protocol_done);
    /* else
         response will be received and treated async wise */
  }

  if(CURLE_OK != code) {
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    if(*in_connect) {
      Curl_disconnect(*in_connect); /* close the connection */
      *in_connect = NULL;           /* return a NULL */
    }
  } else {
      if ((*in_connect)->is_in_pipeline)
          data->state.is_in_pipeline = TRUE;
  }

  return code;
}

/* Call this function after Curl_connect() has returned async=TRUE and
   then a successful name resolve has been received.

   Note: this function disconnects and frees the conn data in case of
   resolve failure */
CURLcode Curl_async_resolved(struct connectdata *conn,
                             bool *protocol_done)
{
#if defined(USE_ARES) || defined(USE_THREADING_GETHOSTBYNAME) || \
    defined(USE_THREADING_GETADDRINFO)
  CURLcode code = SetupConnection(conn, conn->async.dns, protocol_done);

  if(code)
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    Curl_disconnect(conn); /* close the connection */

  return code;
#else
  (void)conn;
  (void)protocol_done;
  return CURLE_OK;
#endif
}


CURLcode Curl_done(struct connectdata **connp,
                   CURLcode status) /* an error if this is called after an
                                       error was detected */
{
  CURLcode result;
  struct connectdata *conn = *connp;
  struct SessionHandle *data = conn->data;

  Curl_expire(data, 0); /* stop timer */

  if(conn->bits.done)
    return CURLE_OK; /* Curl_done() has already been called */

  conn->bits.done = TRUE; /* called just now! */

  /* cleanups done even if the connection is re-used */

  if(data->reqdata.rangestringalloc) {
    free(data->reqdata.range);
    data->reqdata.rangestringalloc = FALSE;
  }

  /* Cleanup possible redirect junk */
  if(data->reqdata.newurl) {
    free(data->reqdata.newurl);
    data->reqdata.newurl = NULL;
  }

  if(conn->dns_entry) {
    Curl_resolv_unlock(data, conn->dns_entry); /* done with this */
    conn->dns_entry = NULL;
  }

  /* this calls the protocol-specific function pointer previously set */
  if(conn->curl_done)
    result = conn->curl_done(conn, status);
  else
    result = CURLE_OK;

  Curl_pgrsDone(conn); /* done with the operation */

  /* for ares-using, make sure all possible outstanding requests are properly
     cancelled before we proceed */
  ares_cancel(data->state.areschannel);

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has
     forced us to close this no matter what we think.

     if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of all our efforts to be nice, due to protocol
     restrictions in our or the server's end */
  if(data->set.reuse_forbid || conn->bits.close) {
    CURLcode res2;
    res2 = Curl_disconnect(conn); /* close the connection */

    *connp = NULL; /* to make the caller of this function better detect that
                      this was actually killed here */

    /* If we had an error already, make sure we return that one. But
       if we got a new error, return that. */
    if(!result && res2)
      result = res2;
  }
  else {
    /* remember the most recently used connection */
    data->state.lastconnect = conn->connectindex;

    infof(data, "Connection #%ld to host %s left intact\n",
          conn->connectindex,
          conn->bits.httpproxy?conn->proxy.dispname:conn->host.dispname);

    ConnectionDone(conn); /* the connection is no longer in use */
  }

  return result;
}

CURLcode Curl_do(struct connectdata **connp, bool *done)
{
  CURLcode result=CURLE_OK;
  struct connectdata *conn = *connp;
  struct SessionHandle *data = conn->data;

  conn->bits.done = FALSE; /* Curl_done() is not called yet */
  conn->bits.do_more = FALSE; /* by default there's no curl_do_more() to use */

  if(conn->curl_do) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->curl_do(conn, done);

    /* This was formerly done in transfer.c, but we better do it here */

    if((CURLE_SEND_ERROR == result) && conn->bits.reuse) {
      /* This was a re-use of a connection and we got a write error in the
       * DO-phase. Then we DISCONNECT this connection and have another attempt
       * to CONNECT and then DO again! The retry cannot possibly find another
       * connection to re-use, since we only keep one possible connection for
       * each.  */

      infof(data, "Re-used connection seems dead, get a new one\n");

      conn->bits.close = TRUE; /* enforce close of this connection */
      result = Curl_done(&conn, result); /* we are so done with this */

      /* conn may no longer be a good pointer */

      /*
       * According to bug report #1330310. We need to check for
       * CURLE_SEND_ERROR here as well. I figure this could happen when the
       * request failed on a FTP connection and thus Curl_done() itself tried
       * to use the connection (again). Slight Lack of feedback in the report,
       * but I don't think this extra check can do much harm.
       */
      if((CURLE_OK == result) || (CURLE_SEND_ERROR == result)) {
        bool async;
        bool protocol_done = TRUE;

        /* Now, redo the connect and get a new connection */
        result = Curl_connect(data, connp, &async, &protocol_done);
        if(CURLE_OK == result) {
          /* We have connected or sent away a name resolve query fine */

          conn = *connp; /* setup conn to again point to something nice */
          if(async) {
            /* Now, if async is TRUE here, we need to wait for the name
               to resolve */
            result = Curl_wait_for_resolv(conn, NULL);
            if(result)
              return result;

            /* Resolved, continue with the connection */
            result = Curl_async_resolved(conn, &protocol_done);
            if(result)
              return result;
          }

          /* ... finally back to actually retry the DO phase */
          result = conn->curl_do(conn, done);
        }
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
