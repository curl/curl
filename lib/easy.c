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

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "strequal.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
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
#include "ssluse.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"
#include "share.h"
#include "memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
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

#ifdef ENABLE_IPV6
  wVersionRequested = MAKEWORD(2, 0);
#else
  wVersionRequested = MAKEWORD(1, 1);
#endif
    
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
static unsigned int  initialized = 0;
static long          init_flags  = 0;

/*
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, we need to have these pointers set already.
 */
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

/**
 * curl_global_init() globally initializes cURL given a bitwise set of the
 * different features of what to initialize.
 */
CURLcode curl_global_init(long flags)
{
  if (initialized)
    return CURLE_OK;

  /* Setup the default memory functions here (again) */
  Curl_cmalloc = (curl_malloc_callback)malloc;
  Curl_cfree = (curl_free_callback)free;
  Curl_crealloc = (curl_realloc_callback)realloc;
  Curl_cstrdup = (curl_strdup_callback)strdup;
  Curl_ccalloc = (curl_calloc_callback)calloc;

  if (flags & CURL_GLOBAL_SSL)
    Curl_SSL_init();

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

  initialized = 1;
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

  Curl_global_host_cache_dtor();

  if (init_flags & CURL_GLOBAL_SSL)
    Curl_SSL_cleanup();

  if (init_flags & CURL_GLOBAL_WIN32)
    win32_cleanup();

#ifdef _AMIGASF
  amiga_cleanup();
#endif

  initialized = 0;
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
typedef int (*func_T)(void);
CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  func_T param_func = (func_T)0;
  long param_long = 0;
  void *param_obj = NULL;
  curl_off_t param_offset = 0;
  struct SessionHandle *data = curl;
  CURLcode ret=CURLE_FAILED_INIT;

  va_start(arg, tag);

  /* PORTING NOTE:
     Object pointers can't necessarily be casted to function pointers and
     therefore we need to know what type it is and read the correct type
     at once. This should also correct problems with different sizes of
     the types.
  */

  if(tag < CURLOPTTYPE_OBJECTPOINT) {
    /* This is a LONG type */
    param_long = va_arg(arg, long);
    ret = Curl_setopt(data, tag, param_long);
  }
  else if(tag < CURLOPTTYPE_FUNCTIONPOINT) {
    /* This is a object pointer type */
    param_obj = va_arg(arg, void *);
    ret = Curl_setopt(data, tag, param_obj);
  }
  else if(tag < CURLOPTTYPE_OFF_T) {
    /* This is a function pointer type */
    param_func = va_arg(arg, func_T );
    ret = Curl_setopt(data, tag, param_func);
  } else {
    /* This is a curl_off_t type */
    param_offset = va_arg(arg, curl_off_t);
    ret = Curl_setopt(data, tag, param_offset);
  }

  va_end(arg);
  return ret;
}

/*
 * curl_easy_perform() is the external interface that performs a transfer
 * previously setup.
 */
CURLcode curl_easy_perform(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if ( ! (data->share && data->share->hostcache) ) {

    if (Curl_global_host_cache_use(data) &&
        data->hostcache != Curl_global_host_cache_get()) {
      if (data->hostcache)
        Curl_hash_destroy(data->hostcache);
      data->hostcache = Curl_global_host_cache_get();
    }

    if (!data->hostcache) {
      data->hostcache = Curl_mk_dnscache();

      if(!data->hostcache)
        /* While we possibly could survive and do good without a host cache,
           the fact that creating it failed indicates that things are truly
           screwed up and we should bail out! */
        return CURLE_OUT_OF_MEMORY;
    }
    
  }
  
  return Curl_perform(data);
}

/*
 * curl_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void curl_easy_cleanup(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  if ( ! (data->share && data->share->hostcache) ) {
    if ( !Curl_global_host_cache_use(data)) {
      Curl_hash_destroy(data->hostcache);
    }
  }
  Curl_close(data);
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
  struct SessionHandle *data=(struct SessionHandle *)incurl;

  struct SessionHandle *outcurl = (struct SessionHandle *)
    malloc(sizeof(struct SessionHandle));

  if(NULL == outcurl)
    return NULL; /* failure */

  /* start with clearing the entire new struct */
  memset(outcurl, 0, sizeof(struct SessionHandle));

#ifdef USE_ARES
  /* If we use ares, we need to setup a new ares channel for the new handle */
  if(ARES_SUCCESS != ares_init(&outcurl->state.areschannel)) {
    free(outcurl);
    return NULL;
  }
#endif

  /*
   * We setup a few buffers we need. We should probably make them
   * get setup on-demand in the code, as that would probably decrease
   * the likeliness of us forgetting to init a buffer here in the future.
   */
  outcurl->state.headerbuff=(char*)malloc(HEADERSIZE);
  if(!outcurl->state.headerbuff) {
    free(outcurl); /* free the memory again */
    return NULL;
  }
  outcurl->state.headersize=HEADERSIZE;

  /* copy all userdefined values */
  outcurl->set = data->set;
  outcurl->state.numconnects = data->state.numconnects;
  outcurl->state.connects = (struct connectdata **)
      malloc(sizeof(struct connectdata *) * outcurl->state.numconnects);

  if(!outcurl->state.connects) {
    free(outcurl->state.headerbuff);
    free(outcurl);
    return NULL;
  }
  memset(outcurl->state.connects, 0,
         sizeof(struct connectdata *)*outcurl->state.numconnects);

  outcurl->progress.flags    = data->progress.flags;
  outcurl->progress.callback = data->progress.callback;

  if(data->cookies)
    /* If cookies are enabled in the parent handle, we enable them
       in the clone as well! */
    outcurl->cookies = Curl_cookie_init(data,
                                        data->cookies->filename,
                                        outcurl->cookies,
                                        data->set.cookiesession);

  /* duplicate all values in 'change' */
  if(data->change.url) {
    outcurl->change.url = strdup(data->change.url);
    outcurl->change.url_alloc = TRUE;
  }
  if(data->change.proxy) {
    outcurl->change.proxy = strdup(data->change.proxy);
    outcurl->change.proxy_alloc = TRUE;
  }
  if(data->change.referer) {
    outcurl->change.referer = strdup(data->change.referer);
    outcurl->change.referer_alloc = TRUE;
  }

  return outcurl;
}
