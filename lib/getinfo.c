/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "urldata.h"
#include "getinfo.h"

#include "curl_memory.h"
#include "sslgen.h"
#include "connect.h" /* Curl_getconnectinfo() */
#include "progress.h"

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
  pro->t_appconnect = 0;
  pro->t_pretransfer = 0;
  pro->t_starttransfer = 0;
  pro->timespent = 0;
  pro->t_redirect = 0;

  info->httpcode = 0;
  info->httpversion=0;
  info->filetime=-1; /* -1 is an illegal time and thus means unknown */

  if(info->contenttype)
    free(info->contenttype);
  info->contenttype = NULL;

  info->header_size = 0;
  info->request_size = 0;
  info->numconnects = 0;

  info->conn_primary_ip[0] = '\0';
  info->conn_local_ip[0] = '\0';
  info->conn_primary_port = 0;
  info->conn_local_port = 0;

  return CURLE_OK;
}

static CURLcode getinfo_char(struct SessionHandle *data, CURLINFO info,
                             char **param_charp)
{
  switch(info) {
  case CURLINFO_EFFECTIVE_URL:
    *param_charp = data->change.url?data->change.url:(char *)"";
    break;
  case CURLINFO_CONTENT_TYPE:
    *param_charp = data->info.contenttype;
    break;
  case CURLINFO_PRIVATE:
    *param_charp = (char *) data->set.private_data;
    break;
  case CURLINFO_FTP_ENTRY_PATH:
    /* Return the entrypath string from the most recent connection.
       This pointer was copied from the connectdata structure by FTP.
       The actual string may be free()ed by subsequent libcurl calls so
       it must be copied to a safer area before the next libcurl call.
       Callers must never free it themselves. */
    *param_charp = data->state.most_recent_ftp_entrypath;
    break;
  case CURLINFO_REDIRECT_URL:
    /* Return the URL this request would have been redirected to if that
       option had been enabled! */
    *param_charp = data->info.wouldredirect;
    break;
  case CURLINFO_PRIMARY_IP:
    /* Return the ip address of the most recent (primary) connection */
    *param_charp = data->info.conn_primary_ip;
    break;
  case CURLINFO_LOCAL_IP:
    /* Return the source/local ip address of the most recent (primary)
       connection */
    *param_charp = data->info.conn_local_ip;
    break;
  case CURLINFO_RTSP_SESSION_ID:
    *param_charp = data->set.str[STRING_RTSP_SESSION_ID];
    break;

  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}

static CURLcode getinfo_long(struct SessionHandle *data, CURLINFO info,
                             long *param_longp)
{
  curl_socket_t sockfd;

  union {
    unsigned long *to_ulong;
    long          *to_long;
  } lptr;

  switch(info) {
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
  case CURLINFO_SSL_VERIFYRESULT:
    *param_longp = data->set.ssl.certverifyresult;
    break;
  case CURLINFO_REDIRECT_COUNT:
    *param_longp = data->set.followlocation;
    break;
  case CURLINFO_HTTPAUTH_AVAIL:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.httpauthavail;
    break;
  case CURLINFO_PROXYAUTH_AVAIL:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.proxyauthavail;
    break;
  case CURLINFO_OS_ERRNO:
    *param_longp = data->state.os_errno;
    break;
  case CURLINFO_NUM_CONNECTS:
    *param_longp = data->info.numconnects;
    break;
  case CURLINFO_LASTSOCKET:
    sockfd = Curl_getconnectinfo(data, NULL);

    /* note: this is not a good conversion for systems with 64 bit sockets and
       32 bit longs */
    if(sockfd != CURL_SOCKET_BAD)
      *param_longp = (long)sockfd;
    else
      /* this interface is documented to return -1 in case of badness, which
         may not be the same as the CURL_SOCKET_BAD value */
      *param_longp = -1;
    break;
  case CURLINFO_PRIMARY_PORT:
    /* Return the (remote) port of the most recent (primary) connection */
    *param_longp = data->info.conn_primary_port;
    break;
  case CURLINFO_LOCAL_PORT:
    /* Return the local port of the most recent (primary) connection */
    *param_longp = data->info.conn_local_port;
    break;
  case CURLINFO_CONDITION_UNMET:
    /* return if the condition prevented the document to get transferred */
    *param_longp = data->info.timecond;
    break;
  case CURLINFO_RTSP_CLIENT_CSEQ:
    *param_longp = data->state.rtsp_next_client_CSeq;
    break;
  case CURLINFO_RTSP_SERVER_CSEQ:
    *param_longp = data->state.rtsp_next_server_CSeq;
    break;
  case CURLINFO_RTSP_CSEQ_RECV:
    *param_longp = data->state.rtsp_CSeq_recv;
    break;

  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}

static CURLcode getinfo_double(struct SessionHandle *data, CURLINFO info,
                               double *param_doublep)
{
  switch(info) {
  case CURLINFO_TOTAL_TIME:
    *param_doublep = data->progress.timespent;
    break;
  case CURLINFO_NAMELOOKUP_TIME:
    *param_doublep = data->progress.t_nslookup;
    break;
  case CURLINFO_CONNECT_TIME:
    *param_doublep = data->progress.t_connect;
    break;
  case CURLINFO_APPCONNECT_TIME:
    *param_doublep = data->progress.t_appconnect;
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
  case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
    *param_doublep = (data->progress.flags & PGRS_DL_SIZE_KNOWN)?
      (double)data->progress.size_dl:-1;
    break;
  case CURLINFO_CONTENT_LENGTH_UPLOAD:
    *param_doublep = (data->progress.flags & PGRS_UL_SIZE_KNOWN)?
      (double)data->progress.size_ul:-1;
    break;
  case CURLINFO_REDIRECT_TIME:
    *param_doublep =  data->progress.t_redirect;
    break;

  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}

static CURLcode getinfo_slist(struct SessionHandle *data, CURLINFO info,
                              struct curl_slist **param_slistp)
{
  union {
    struct curl_certinfo * to_certinfo;
    struct curl_slist    * to_slist;
  } ptr;

  switch(info) {
  case CURLINFO_SSL_ENGINES:
    *param_slistp = Curl_ssl_engines_list(data);
    break;
  case CURLINFO_COOKIELIST:
    *param_slistp = Curl_cookie_list(data);
    break;
  case CURLINFO_CERTINFO:
    /* Return the a pointer to the certinfo struct. Not really an slist
       pointer but we can pretend it is here */
    ptr.to_certinfo = &data->info.certs;
    *param_slistp = ptr.to_slist;
    break;

  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return CURLE_OK;
}

CURLcode Curl_getinfo(struct SessionHandle *data, CURLINFO info, ...)
{
  va_list arg;
  long *param_longp=NULL;
  double *param_doublep=NULL;
  char **param_charp=NULL;
  struct curl_slist **param_slistp=NULL;
  int type;
  /* default return code is to error out! */
  CURLcode ret = CURLE_BAD_FUNCTION_ARGUMENT;

  if(!data)
    return ret;

  va_start(arg, info);

  type = CURLINFO_TYPEMASK & (int)info;
  switch(type) {
  case CURLINFO_STRING:
    param_charp = va_arg(arg, char **);
    if(NULL != param_charp)
      ret = getinfo_char(data, info, param_charp);
    break;
  case CURLINFO_LONG:
    param_longp = va_arg(arg, long *);
    if(NULL != param_longp)
      ret = getinfo_long(data, info, param_longp);
    break;
  case CURLINFO_DOUBLE:
    param_doublep = va_arg(arg, double *);
    if(NULL != param_doublep)
      ret = getinfo_double(data, info, param_doublep);
    break;
  case CURLINFO_SLIST:
    param_slistp = va_arg(arg, struct curl_slist **);
    if(NULL != param_slistp)
      ret = getinfo_slist(data, info, param_slistp);
    break;
  default:
    break;
  }

  va_end(arg);
  return ret;
}
