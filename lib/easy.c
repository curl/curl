/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* -- WIN32 approved -- */
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

#include "strequal.h"

#ifdef WIN32
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

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#endif  /* WIN32 ... */

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sslgen.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"
#include "share.h"
#include "strdup.h"
#include "memory.h"
#include "progress.h"
#include "easyif.h"
#include "sendf.h" /* for failf function prototype */
#include <ca-bundle.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
#include <iconv.h>
/* set default codesets for iconv */
#ifndef CURL_ICONV_CODESET_OF_NETWORK
#define CURL_ICONV_CODESET_OF_NETWORK "ISO8859-1"
#endif
#ifndef CURL_ICONV_CODESET_FOR_UTF8
#define CURL_ICONV_CODESET_FOR_UTF8   "UTF-8"
#endif
#define ICONV_ERROR  (size_t)-1
#endif /* CURL_DOES_CONVERSIONS && HAVE_ICONV */

/* The last #include file should be: */
#include "memdebug.h"

#ifdef USE_WINSOCK
/* win32_cleanup() is for win32 socket cleanup functionality, the opposite
   of win32_init() */
static void win32_cleanup(void)
{
  WSACleanup();
}

/* win32_init() performs win32 socket initialization to properly setup the
   stack to allow networking */
static CURLcode win32_init(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

#if defined(ENABLE_IPV6) && (USE_WINSOCK < 2)
  Error IPV6_requires_winsock2
#endif

  wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

  err = WSAStartup(wVersionRequested, &wsaData);

  if (err != 0)
    /* Tell the user that we couldn't find a useable */
    /* winsock.dll.     */
    return CURLE_FAILED_INIT;

  /* Confirm that the Windows Sockets DLL supports what we need.*/
  /* Note that if the DLL supports versions greater */
  /* than wVersionRequested, it will still return */
  /* wVersionRequested in wVersion. wHighVersion contains the */
  /* highest supported version. */

  if ( LOBYTE( wsaData.wVersion ) != LOBYTE(wVersionRequested) ||
       HIBYTE( wsaData.wVersion ) != HIBYTE(wVersionRequested) ) {
    /* Tell the user that we couldn't find a useable */

    /* winsock.dll. */
    WSACleanup();
    return CURLE_FAILED_INIT;
  }
  /* The Windows Sockets DLL is acceptable. Proceed. */
  return CURLE_OK;
}

#else
/* These functions exist merely to prevent compiler warnings */
static CURLcode win32_init(void) { return CURLE_OK; }
static void win32_cleanup(void) { }
#endif

#ifdef USE_LIBIDN
/*
 * Initialise use of IDNA library.
 * It falls back to ASCII if $CHARSET isn't defined. This doesn't work for
 * idna_to_ascii_lz().
 */
static void idna_init (void)
{
#ifdef WIN32
  char buf[60];
  UINT cp = GetACP();

  if (!getenv("CHARSET") && cp > 0) {
    snprintf(buf, sizeof(buf), "CHARSET=cp%u", cp);
    putenv(buf);
  }
#else
  /* to do? */
#endif
}
#endif  /* USE_LIBIDN */

/* true globals -- for curl_global_init() and curl_global_cleanup() */
static unsigned int  initialized;
static long          init_flags;

/*
 * strdup (and other memory functions) is redefined in complicated
 * ways, but at this point it must be defined as the system-supplied strdup
 * so the callback pointer is initialized correctly.
 */
#if defined(_WIN32_WCE)
#define system_strdup _strdup
#elif !defined(HAVE_STRDUP)
#define system_strdup curlx_strdup
#else
#define system_strdup strdup
#endif

/*
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, we need to have these pointers set already.
 */

curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

/**
 * curl_global_init() globally initializes cURL given a bitwise set of the
 * different features of what to initialize.
 */
CURLcode curl_global_init(long flags)
{
  if (initialized++)
    return CURLE_OK;

  /* Setup the default memory functions here (again) */
  Curl_cmalloc = (curl_malloc_callback)malloc;
  Curl_cfree = (curl_free_callback)free;
  Curl_crealloc = (curl_realloc_callback)realloc;
  Curl_cstrdup = (curl_strdup_callback)system_strdup;
  Curl_ccalloc = (curl_calloc_callback)calloc;

  if (flags & CURL_GLOBAL_SSL)
    if (!Curl_ssl_init())
      return CURLE_FAILED_INIT;

  if (flags & CURL_GLOBAL_WIN32)
    if (win32_init() != CURLE_OK)
      return CURLE_FAILED_INIT;

#ifdef _AMIGASF
  if(!amiga_init())
    return CURLE_FAILED_INIT;
#endif

#ifdef USE_LIBIDN
  idna_init();
#endif

  init_flags  = flags;

  return CURLE_OK;
}

/*
 * curl_global_init_mem() globally initializes cURL and also registers the
 * user provided callback routines.
 */
CURLcode curl_global_init_mem(long flags, curl_malloc_callback m,
                              curl_free_callback f, curl_realloc_callback r,
                              curl_strdup_callback s, curl_calloc_callback c)
{
  CURLcode code = CURLE_OK;

  /* Invalid input, return immediately */
  if (!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  /* Already initialized, don't do it again */
  if ( initialized )
    return CURLE_OK;

  /* Call the actual init function first */
  code = curl_global_init(flags);
  if (code == CURLE_OK) {
    Curl_cmalloc = m;
    Curl_cfree = f;
    Curl_cstrdup = s;
    Curl_crealloc = r;
    Curl_ccalloc = c;
  }

  return code;
}

/**
 * curl_global_cleanup() globally cleanups cURL, uses the value of
 * "init_flags" to determine what needs to be cleaned up and what doesn't.
 */
void curl_global_cleanup(void)
{
  if (!initialized)
    return;

  if (--initialized)
    return;

  Curl_global_host_cache_dtor();

  if (init_flags & CURL_GLOBAL_SSL)
    Curl_ssl_cleanup();

  if (init_flags & CURL_GLOBAL_WIN32)
    win32_cleanup();

#ifdef _AMIGASF
  amiga_cleanup();
#endif

  init_flags  = 0;
}

/*
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
CURL *curl_easy_init(void)
{
  CURLcode res;
  struct SessionHandle *data;

  /* Make sure we inited the global SSL stuff */
  if (!initialized) {
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(res)
      /* something in the global init failed, return nothing */
      return NULL;
  }

  /* We use curl_open() with undefined URL so far */
  res = Curl_open(&data);
  if(res != CURLE_OK)
    return NULL;

  return data;
}

/*
 * curl_easy_setopt() is the external interface for setting options on an
 * easy handle.
 */

CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  struct SessionHandle *data = curl;
  CURLcode ret;

  if(!curl)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  ret = Curl_setopt(data, tag, arg);

  va_end(arg);
  return ret;
}

#ifdef CURL_MULTIEASY
/***************************************************************************
 * This function is still only for testing purposes. It makes a great way
 * to run the full test suite on the multi interface instead of the easy one.
 ***************************************************************************
 *
 * The *new* curl_easy_perform() is the external interface that performs a
 * transfer previously setup.
 *
 * Wrapper-function that: creates a multi handle, adds the easy handle to it,
 * runs curl_multi_perform() until the transfer is done, then detaches the
 * easy handle, destroys the multi handle and returns the easy handle's return
 * code. This will make everything internally use and assume multi interface.
 */
CURLcode curl_easy_perform(CURL *easy)
{
  CURLM *multi;
  CURLMcode mcode;
  CURLcode code = CURLE_OK;
  int still_running;
  struct timeval timeout;
  int rc;
  CURLMsg *msg;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  int maxfd;

  if(!easy)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  multi = curl_multi_init();
  if(!multi)
    return CURLE_OUT_OF_MEMORY;

  mcode = curl_multi_add_handle(multi, easy);
  if(mcode) {
    curl_multi_cleanup(multi);
    return CURLE_FAILED_INIT;
  }

  /* we start some action by calling perform right away */

  do {
    while(CURLM_CALL_MULTI_PERFORM ==
          curl_multi_perform(multi, &still_running));

    if(!still_running)
      break;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* timeout once per second */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* get file descriptors from the transfers */
    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);

    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    if(rc == -1)
      /* select error */
      break;

    /* timeout or data to send/receive => loop! */
  } while(still_running);

  msg = curl_multi_info_read(multi, &rc);
  if(msg)
    code = msg->data.result;

  mcode = curl_multi_remove_handle(multi, easy);
  /* what to do if it fails? */

  mcode = curl_multi_cleanup(multi);
  /* what to do if it fails? */

  return code;
}
#else
/*
 * curl_easy_perform() is the external interface that performs a transfer
 * previously setup.
 */
CURLcode curl_easy_perform(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if ( ! (data->share && data->share->hostcache) ) {

    if (Curl_global_host_cache_use(data) &&
        (data->dns.hostcachetype != HCACHE_GLOBAL)) {
      if (data->dns.hostcachetype == HCACHE_PRIVATE)
        Curl_hash_destroy(data->dns.hostcache);
      data->dns.hostcache = Curl_global_host_cache_get();
      data->dns.hostcachetype = HCACHE_GLOBAL;
    }

    if (!data->dns.hostcache) {
      data->dns.hostcachetype = HCACHE_PRIVATE;
      data->dns.hostcache = Curl_mk_dnscache();

      if(!data->dns.hostcache)
        /* While we possibly could survive and do good without a host cache,
           the fact that creating it failed indicates that things are truly
           screwed up and we should bail out! */
        return CURLE_OUT_OF_MEMORY;
    }

  }

  if(!data->state.connc) {
    /* oops, no connection cache, make one up */
    data->state.connc = Curl_mk_connc(CONNCACHE_PRIVATE, -1);
    if(!data->state.connc)
      return CURLE_OUT_OF_MEMORY;
  }

  return Curl_perform(data);
}
#endif

/*
 * curl_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void curl_easy_cleanup(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if(!data)
    return;

  Curl_close(data);
}

/*
 * Store a pointed to the multi handle within the easy handle's data struct.
 */
void Curl_easy_addmulti(struct SessionHandle *data,
                        void *multi)
{
  data->multi = multi;
}

void Curl_easy_initHandleData(struct SessionHandle *data)
{
    memset(&data->reqdata, 0, sizeof(struct HandleData));

    data->reqdata.maxdownload = -1;
}

/*
 * curl_easy_getinfo() is an external interface that allows an app to retrieve
 * information from a performed transfer and similar.
 */
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  return Curl_getinfo(data, info, paramp);
}

/*
 * curl_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working handle
 * with all options set exactly as the input source handle.
 */
CURL *curl_easy_duphandle(CURL *incurl)
{
  bool fail = TRUE;
  struct SessionHandle *data=(struct SessionHandle *)incurl;

  struct SessionHandle *outcurl = (struct SessionHandle *)
    calloc(sizeof(struct SessionHandle), 1);

  if(NULL == outcurl)
    return NULL; /* failure */

  do {

    /*
     * We setup a few buffers we need. We should probably make them
     * get setup on-demand in the code, as that would probably decrease
     * the likeliness of us forgetting to init a buffer here in the future.
     */
    outcurl->state.headerbuff=(char*)malloc(HEADERSIZE);
    if(!outcurl->state.headerbuff) {
      break;
    }
    outcurl->state.headersize=HEADERSIZE;

    /* copy all userdefined values */
    outcurl->set = data->set;

    if(data->state.used_interface == Curl_if_multi)
      outcurl->state.connc = data->state.connc;
    else
      outcurl->state.connc = Curl_mk_connc(CONNCACHE_PRIVATE, -1);

    if(!outcurl->state.connc)
      break;

    outcurl->state.lastconnect = -1;

    outcurl->progress.flags    = data->progress.flags;
    outcurl->progress.callback = data->progress.callback;

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
    if(data->cookies) {
      /* If cookies are enabled in the parent handle, we enable them
         in the clone as well! */
      outcurl->cookies = Curl_cookie_init(data,
                                            data->cookies->filename,
                                            outcurl->cookies,
                                            data->set.cookiesession);
      if(!outcurl->cookies) {
        break;
      }
    }
#endif   /* CURL_DISABLE_HTTP */

    /* duplicate all values in 'change' */

    if(data->change.url) {
      outcurl->change.url = strdup(data->change.url);
      if(!outcurl->change.url)
        break;
      outcurl->change.url_alloc = TRUE;
    }

    if(data->change.referer) {
      outcurl->change.referer = strdup(data->change.referer);
      if(!outcurl->change.referer)
        break;
      outcurl->change.referer_alloc = TRUE;
    }

#ifdef USE_ARES
    /* If we use ares, we setup a new ares channel for the new handle */
    if(ARES_SUCCESS != ares_init(&outcurl->state.areschannel))
      break;
#endif

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
    outcurl->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                     CURL_ICONV_CODESET_OF_NETWORK);
    outcurl->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                      CURL_ICONV_CODESET_OF_HOST);
    outcurl->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                  CURL_ICONV_CODESET_FOR_UTF8);
#endif

    Curl_easy_initHandleData(outcurl);

    outcurl->magic = CURLEASY_MAGIC_NUMBER;

    fail = FALSE; /* we reach this point and thus we are OK */

  } while(0);

  if(fail) {
    if(outcurl) {
      if(outcurl->state.connc->type == CONNCACHE_PRIVATE)
        Curl_rm_connc(outcurl->state.connc);
      if(outcurl->state.headerbuff)
        free(outcurl->state.headerbuff);
      if(outcurl->change.url)
        free(outcurl->change.url);
      if(outcurl->change.referer)
        free(outcurl->change.referer);
      free(outcurl); /* free the memory again */
      outcurl = NULL;
    }
  }

  return outcurl;
}

/*
 * curl_easy_reset() is an external interface that allows an app to re-
 * initialize a session handle to the default values.
 */
void curl_easy_reset(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  Curl_safefree(data->reqdata.pathbuffer);
  data->reqdata.pathbuffer=NULL;

  Curl_safefree(data->reqdata.proto.generic);
  data->reqdata.proto.generic=NULL;

  /* zero out UserDefined data: */
  memset(&data->set, 0, sizeof(struct UserDefined));

  /* zero out Progress data: */
  memset(&data->progress, 0, sizeof(struct Progress));

  /* init Handle data */
  Curl_easy_initHandleData(data);

  /* The remainder of these calls have been taken from Curl_open() */

  data->set.out = stdout; /* default output to stdout */
  data->set.in  = stdin;  /* default input from stdin */
  data->set.err  = stderr;  /* default stderr to stderr */

  /* use fwrite as default function to store output */
  data->set.fwrite = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  data->set.fread = (curl_read_callback)fread;

  data->set.infilesize = -1; /* we don't know any size */
  data->set.postfieldsize = -1;

  data->state.current_speed = -1; /* init to negative == impossible */

  data->set.httpreq = HTTPREQ_GET; /* Default HTTP request */
  data->set.ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
  data->set.ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */

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

  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  data->set.ssl.verifypeer = TRUE;
  data->set.ssl.verifyhost = 2;
#ifdef CURL_CA_BUNDLE
  /* This is our prefered CA cert bundle since install time */
  data->set.ssl.CAfile = (char *)CURL_CA_BUNDLE;
#endif

  data->set.ssh_auth_types = CURLSSH_AUTH_DEFAULT; /* defaults to any auth
                                                      type */
}

#ifdef CURL_DOES_CONVERSIONS
/*
 * Curl_convert_to_network() is an internal function
 * for performing ASCII conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_to_network(struct SessionHandle *data,
                                 char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convtonetwork) {
    /* use translation callback */
    rc = data->set.convtonetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_TO_NETWORK_FUNCTION callback returned %i: %s",
            rc, curl_easy_strerror(rc));
    }
    return(rc);
  } else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;

    /* open an iconv conversion descriptor if necessary */
    if(data->outbound_cd == (iconv_t)-1) {
      data->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                     CURL_ICONV_CODESET_OF_HOST);
      if(data->outbound_cd == (iconv_t)-1) {
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
               CURL_ICONV_CODESET_OF_NETWORK,
               CURL_ICONV_CODESET_OF_HOST,
               errno, strerror(errno));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->outbound_cd, (const char**)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if ((rc == ICONV_ERROR) || (in_bytes != 0)) {
      failf(data,
        "The Curl_convert_to_network iconv call failed with errno %i: %s",
             errno, strerror(errno));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_TO_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_network() is an internal function
 * for performing ASCII conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_from_network(struct SessionHandle *data,
                                      char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromnetwork) {
    /* use translation callback */
    rc = data->set.convfromnetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback returned %i: %s",
            rc, curl_easy_strerror(rc));
    }
    return(rc);
  } else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;

    /* open an iconv conversion descriptor if necessary */
    if(data->inbound_cd == (iconv_t)-1) {
      data->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                    CURL_ICONV_CODESET_OF_NETWORK);
      if(data->inbound_cd == (iconv_t)-1) {
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
               CURL_ICONV_CODESET_OF_HOST,
               CURL_ICONV_CODESET_OF_NETWORK,
               errno, strerror(errno));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->inbound_cd, (const char **)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if ((rc == ICONV_ERROR) || (in_bytes != 0)) {
      failf(data,
        "The Curl_convert_from_network iconv call failed with errno %i: %s",
             errno, strerror(errno));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_utf8() is an internal function
 * for performing UTF-8 conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_from_utf8(struct SessionHandle *data,
                                     char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromutf8) {
    /* use translation callback */
    rc = data->set.convfromutf8(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_UTF8_FUNCTION callback returned %i: %s",
            rc, curl_easy_strerror(rc));
    }
    return(rc);
  } else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;

    /* open an iconv conversion descriptor if necessary */
    if(data->utf8_cd == (iconv_t)-1) {
      data->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                 CURL_ICONV_CODESET_FOR_UTF8);
      if(data->utf8_cd == (iconv_t)-1) {
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
               CURL_ICONV_CODESET_OF_HOST,
               CURL_ICONV_CODESET_FOR_UTF8,
               errno, strerror(errno));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->utf8_cd, (const char**)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if ((rc == ICONV_ERROR) || (in_bytes != 0)) {
      failf(data,
        "The Curl_convert_from_utf8 iconv call failed with errno %i: %s",
             errno, strerror(errno));
      return CURLE_CONV_FAILED;
    }
    if (output_ptr < input_ptr) {
      /* null terminate the now shorter output string */
      *output_ptr = 0x00;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_UTF8_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

#endif /* CURL_DOES_CONVERSIONS */
