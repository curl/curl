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

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "ssluse.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>


/* Silly win32 socket initialization functions */

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
static void win32_cleanup(void)
{
  WSACleanup();
}

static CURLcode win32_init(void)
{
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(2, 0); 
    
  err = WSAStartup(wVersionRequested, &wsaData); 
    
  if (err != 0) 
    /* Tell the user that we couldn't find a useable */ 
    /* winsock.dll.     */ 
    return CURLE_FAILED_INIT; 
    
  /* Confirm that the Windows Sockets DLL supports 2.0.*/ 
  /* Note that if the DLL supports versions greater */ 
  /* than 2.0 in addition to 2.0, it will still return */ 
  /* 2.0 in wVersion since that is the version we */ 
  /* requested. */ 
    
  if ( LOBYTE( wsaData.wVersion ) != 2 || 
       HIBYTE( wsaData.wVersion ) != 0 ) { 
    /* Tell the user that we couldn't find a useable */ 

    /* winsock.dll. */ 
    WSACleanup(); 
    return CURLE_FAILED_INIT; 
  }
  return CURLE_OK;
}
/* The Windows Sockets DLL is acceptable. Proceed. */ 
#else
/* These functions exist merely to prevent compiler warnings */
static CURLcode win32_init(void) { return CURLE_OK; }
static void win32_cleanup(void) { }
#endif


/* true globals -- for curl_global_init() and curl_global_cleanup() */
static unsigned int  initialized = 0;
static long          init_flags  = 0;

/**
 * Globally initializes cURL given a bitwise set of 
 * the different features to initialize.
 */
CURLcode curl_global_init(long flags)
{
  if (initialized)
    return CURLE_OK;

  if (flags & CURL_GLOBAL_SSL)
    Curl_SSL_init();

  if (flags & CURL_GLOBAL_WIN32)
    if (win32_init() != CURLE_OK)
      return CURLE_FAILED_INIT;

  initialized = 1;
  init_flags  = flags;
  
  return CURLE_OK;
}

/**
 * Globally cleanup cURL, uses the value of "init_flags" to determine
 * what needs to be cleaned up and what doesn't
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

  initialized = 0;
  init_flags  = 0;
}

CURL *curl_easy_init(void)
{
  CURLcode res;
  struct SessionHandle *data;

  /* Make sure we inited the global SSL stuff */
  if (!initialized)
    curl_global_init(CURL_GLOBAL_DEFAULT);

  /* We use curl_open() with undefined URL so far */
  res = Curl_open(&data);
  if(res != CURLE_OK)
    return NULL;

  return data;
}

typedef int (*func_T)(void);
CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  func_T param_func = (func_T)0;
  long param_long = 0;
  void *param_obj = NULL;
  struct SessionHandle *data = curl;

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
    Curl_setopt(data, tag, param_long);
  }
  else if(tag < CURLOPTTYPE_FUNCTIONPOINT) {
    /* This is a object pointer type */
    param_obj = va_arg(arg, void *);
    Curl_setopt(data, tag, param_obj);
  }
  else {
    param_func = va_arg(arg, func_T );
    Curl_setopt(data, tag, param_func);
  }

  va_end(arg);
  return CURLE_OK;
}

CURLcode curl_easy_perform(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if (!data->hostcache) {
    if (Curl_global_host_cache_use(data)) {
      data->hostcache = Curl_global_host_cache_get();
    }
    else {
      data->hostcache = Curl_hash_alloc(7, Curl_freeaddrinfo);
    }
  }

  return Curl_perform(data);
}

void curl_easy_cleanup(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  if (!Curl_global_host_cache_use(data)) {
    Curl_hash_destroy(data->hostcache);
  }
  Curl_close(data);
}

CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  return Curl_getinfo(data, info, paramp);
}

CURL *curl_easy_duphandle(CURL *incurl)
{
  struct SessionHandle *data=(struct SessionHandle *)incurl;

  struct SessionHandle *outcurl = (struct SessionHandle *)
    malloc(sizeof(struct SessionHandle));

  if(NULL == outcurl)
    return NULL; /* failure */

  /* start with clearing the entire new struct */
  memset(outcurl, 0, sizeof(struct SessionHandle));

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
    outcurl->cookies = Curl_cookie_init(data->cookies->filename,
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

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
