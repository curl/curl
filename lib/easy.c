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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

CURLcode curl_global_init(long flags)
{
  flags = 0; /* not currently used */
  Curl_SSL_init();
  return CURLE_OK;
}

void curl_global_cleanup(void)
{
  Curl_SSL_cleanup();
}

CURL *curl_easy_init(void)
{
  CURLcode res;
  struct UrlData *data;

  /* Make sure we inited the global SSL stuff */
  Curl_SSL_init();

  /* We use curl_open() with undefined URL so far */
  res = Curl_open((CURL **)&data, NULL);
  if(res != CURLE_OK)
    return NULL;

  /* SAC */
  data->device = NULL;

  return data;
}

typedef int (*func_T)(void);
CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  func_T param_func = (func_T)0;
  long param_long = 0;
  void *param_obj = NULL;
  struct UrlData *data = curl;

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
  return Curl_perform(curl);
}

void curl_easy_cleanup(CURL *curl)
{
  Curl_close(curl);
}

CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  va_start(arg, info);
  paramp = va_arg(arg, void *);

  return Curl_getinfo(curl, info, paramp);
}
