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

#include <curl/curl.h>

#include "urldata.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

CURLcode curl_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  long *param_longp;
  double *param_doublep;
  char **param_charp;
  struct UrlData *data = (struct UrlData *)curl;
  va_start(arg, info);

  switch(info&CURLINFO_TYPEMASK) {
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case CURLINFO_STRING:
    param_charp = va_arg(arg, char **);  
    if(NULL == param_charp)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  case CURLINFO_LONG:
    param_longp = va_arg(arg, long *);
    if(NULL == param_longp)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  case CURLINFO_DOUBLE:
    param_doublep = va_arg(arg, double *);
    if(NULL == param_doublep)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }
  
  switch(info) {
  case CURLINFO_EFFECTIVE_URL:
    *param_charp = data->url?data->url:"";
    break;
  case CURLINFO_HTTP_CODE:
    *param_longp = data->progress.httpcode;
    break;
  case CURLINFO_FILETIME:
    *param_longp = data->progress.filetime;
    break;
  case CURLINFO_HEADER_SIZE:
    *param_longp = data->header_size;
    break;
  case CURLINFO_REQUEST_SIZE:
    *param_longp = data->request_size;
    break;
  case CURLINFO_TOTAL_TIME:
    *param_doublep = data->progress.timespent;
    break;
  case CURLINFO_NAMELOOKUP_TIME:
    *param_doublep = data->progress.t_nslookup;
    break;
  case CURLINFO_CONNECT_TIME:
    *param_doublep = data->progress.t_connect;
    break;
  case CURLINFO_PRETRANSFER_TIME:
    *param_doublep =  data->progress.t_pretransfer;
    break;
  case CURLINFO_SIZE_UPLOAD:
    *param_doublep =  data->progress.uploaded;
    break;
  case CURLINFO_SIZE_DOWNLOAD:
    *param_doublep = data->progress.downloaded;
    break;
  case CURLINFO_SPEED_DOWNLOAD:
    *param_doublep =  data->progress.dlspeed;
    break;
  case CURLINFO_SPEED_UPLOAD:
    *param_doublep = data->progress.ulspeed;
    break;
  case CURLINFO_SSL_VERIFYRESULT:
    *param_longp = data->ssl.certverifyresult;
    break;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}
