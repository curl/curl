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
#include "highlevel.h"
#include <curl/types.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

CURL *curl_easy_init(void)
{
  CURLcode res;
  struct UrlData *data;

  if(curl_init())
    return NULL;

  /* We use curl_open() with undefined URL so far */
  res = curl_open((CURL **)&data, NULL);
  if(res != CURLE_OK)
    return NULL;

  data->interf = CURLI_EASY; /* mark it as an easy one */
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
    curl_setopt(data, tag, param_long);
  }
  else if(tag < CURLOPTTYPE_FUNCTIONPOINT) {
    /* This is a object pointer type */
    param_obj = va_arg(arg, void *);
    curl_setopt(data, tag, param_obj);
  }
  else {
    param_func = va_arg(arg, func_T );
    curl_setopt(data, tag, param_func);
  }

  va_end(arg);
  return CURLE_OK;
}

CURLcode curl_easy_perform(CURL *curl)
{
  return curl_transfer(curl);
}

void curl_easy_cleanup(CURL *curl)
{
  curl_close(curl);
  curl_free();
}
