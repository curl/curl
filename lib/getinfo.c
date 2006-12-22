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

#include "setup.h"

#include <curl/curl.h>

#include "urldata.h"
#include "getinfo.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "memory.h"
#include "sslgen.h"

/* Make this the last #include */
#include "memdebug.h"

/*
 * This is supposed to be called in the beginning of a perform() session
 * and should reset all session-info variables
 */
CURLcode Curl_initinfo(struct SessionHandle *data)
{
  struct Progress *pro = &data->progress;
  struct PureInfo *info =&data->info;

  pro->t_nslookup = 0;
  pro->t_connect = 0;
  pro->t_pretransfer = 0;
  pro->t_starttransfer = 0;
  pro->timespent = 0;
  pro->t_redirect = 0;

  info->httpcode = 0;
  info->httpversion=0;
  info->filetime=-1; /* -1 is an illegal time and thus means unknown */

  if (info->contenttype)
    free(info->contenttype);
  info->contenttype = NULL;

  info->header_size = 0;
  info->request_size = 0;
  info->numconnects = 0;
  return CURLE_OK;
}

CURLcode Curl_getinfo(struct SessionHandle *data, CURLINFO info, ...)
{
  va_list arg;
  long *param_longp=NULL;
  double *param_doublep=NULL;
  char **param_charp=NULL;
  struct curl_slist **param_slistp=NULL;
  char buf;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

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
  case CURLINFO_SLIST:
    param_slistp = va_arg(arg, struct curl_slist **);
    if(NULL == param_slistp)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }

  switch(info) {
  case CURLINFO_EFFECTIVE_URL:
    *param_charp = data->change.url?data->change.url:(char *)"";
    break;
  case CURLINFO_RESPONSE_CODE:
    *param_longp = data->info.httpcode;
    break;
  case CURLINFO_HTTP_CONNECTCODE:
    *param_longp = data->info.httpproxycode;
    break;
  case CURLINFO_FILETIME:
    *param_longp = data->info.filetime;
    break;
  case CURLINFO_HEADER_SIZE:
    *param_longp = data->info.header_size;
    break;
  case CURLINFO_REQUEST_SIZE:
    *param_longp = data->info.request_size;
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
  case CURLINFO_STARTTRANSFER_TIME:
    *param_doublep = data->progress.t_starttransfer;
    break;
  case CURLINFO_SIZE_UPLOAD:
    *param_doublep =  (double)data->progress.uploaded;
    break;
  case CURLINFO_SIZE_DOWNLOAD:
    *param_doublep = (double)data->progress.downloaded;
    break;
  case CURLINFO_SPEED_DOWNLOAD:
    *param_doublep =  (double)data->progress.dlspeed;
    break;
  case CURLINFO_SPEED_UPLOAD:
    *param_doublep = (double)data->progress.ulspeed;
    break;
  case CURLINFO_SSL_VERIFYRESULT:
    *param_longp = data->set.ssl.certverifyresult;
    break;
  case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
    *param_doublep = (double)data->progress.size_dl;
    break;
  case CURLINFO_CONTENT_LENGTH_UPLOAD:
    *param_doublep = (double)data->progress.size_ul;
    break;
  case CURLINFO_REDIRECT_TIME:
    *param_doublep =  data->progress.t_redirect;
    break;
  case CURLINFO_REDIRECT_COUNT:
    *param_longp = data->set.followlocation;
    break;
  case CURLINFO_CONTENT_TYPE:
    *param_charp = data->info.contenttype;
    break;
  case CURLINFO_PRIVATE:
    *param_charp = data->set.private_data;
    break;
  case CURLINFO_HTTPAUTH_AVAIL:
    *param_longp = data->info.httpauthavail;
    break;
  case CURLINFO_PROXYAUTH_AVAIL:
    *param_longp = data->info.proxyauthavail;
    break;
  case CURLINFO_OS_ERRNO:
    *param_longp = data->state.os_errno;
    break;
  case CURLINFO_NUM_CONNECTS:
    *param_longp = data->info.numconnects;
    break;
  case CURLINFO_SSL_ENGINES:
    *param_slistp = Curl_ssl_engines_list(data);
    break;
  case CURLINFO_COOKIELIST:
    *param_slistp = Curl_cookie_list(data);
    break;
  case CURLINFO_FTP_ENTRY_PATH:
    /* Return the entrypath string from the most recent connection.
       This pointer was copied from the connectdata structure by FTP.
       The actual string may be free()ed by subsequent libcurl calls so
       it must be copied to a safer area before the next libcurl call.
       Callers must never free it themselves. */
    *param_charp = data->state.most_recent_ftp_entrypath;
    break;
  case CURLINFO_LASTSOCKET:
    if((data->state.lastconnect != -1) &&
       (data->state.connc->connects[data->state.lastconnect] != NULL)) {
      struct connectdata *c = data->state.connc->connects
        [data->state.lastconnect];
      *param_longp = c->sock[FIRSTSOCKET];
      /* we have a socket connected, let's determine if the server shut down */
      /* determine if ssl */
      if(c->ssl[FIRSTSOCKET].use) {
        /* use the SSL context */
        if (!Curl_ssl_check_cxn(c))
          *param_longp = -1;   /* FIN received */
      }
/* Minix 3.1 doesn't support any flags on recv; just assume socket is OK */
#ifdef MSG_PEEK
      else {
        /* use the socket */
        if(recv((RECV_TYPE_ARG1)c->sock[FIRSTSOCKET], (RECV_TYPE_ARG2)&buf,
                (RECV_TYPE_ARG3)1, (RECV_TYPE_ARG4)MSG_PEEK) == 0) {
          *param_longp = -1;   /* FIN received */
        }
      }
#endif
    }
    else
      *param_longp = -1;
    break;
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}
