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
 *  Portions created by the Initial Developer are Copyright (C) 1999.
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
    *param_doublep = tvdiff(data->progress.t_nslookup,
                            data->progress.start);
    break;
  case CURLINFO_CONNECT_TIME:
    *param_doublep =  tvdiff(data->progress.t_connect,
                             data->progress.start);
    break;
  case CURLINFO_PRETRANSFER_TIME:
    *param_doublep =  tvdiff(data->progress.t_pretransfer,
                             data->progress.start);
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
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}
