/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#include <fetch/fetch.h>

#include "urldata.h"
#include "getinfo.h"

#include "vtls/vtls.h"
#include "connect.h" /* Curl_getconnectinfo() */
#include "progress.h"

/* The last #include files should be: */
#include "fetch_memory.h"
#include "memdebug.h"

/*
 * Initialize statistical and informational data.
 *
 * This function is called in fetch_easy_reset, fetch_easy_duphandle and at the
 * beginning of a perform session. It must reset the session-info variables,
 * in particular all variables in struct PureInfo.
 */
FETCHcode Curl_initinfo(struct Curl_easy *data)
{
  struct Progress *pro = &data->progress;
  struct PureInfo *info = &data->info;

  pro->t_nslookup = 0;
  pro->t_connect = 0;
  pro->t_appconnect = 0;
  pro->t_pretransfer = 0;
  pro->t_posttransfer = 0;
  pro->t_starttransfer = 0;
  pro->timespent = 0;
  pro->t_redirect = 0;
  pro->is_t_startransfer_set = FALSE;

  info->httpcode = 0;
  info->httpproxycode = 0;
  info->httpversion = 0;
  info->filetime = -1; /* -1 is an illegal time and thus means unknown */
  info->timecond = FALSE;

  info->header_size = 0;
  info->request_size = 0;
  info->proxyauthavail = 0;
  info->httpauthavail = 0;
  info->proxyauthpicked = 0;
  info->httpauthpicked = 0;
  info->numconnects = 0;

  free(info->contenttype);
  info->contenttype = NULL;

  free(info->wouldredirect);
  info->wouldredirect = NULL;

  memset(&info->primary, 0, sizeof(info->primary));
  info->primary.remote_port = -1;
  info->primary.local_port = -1;
  info->retry_after = 0;

  info->conn_scheme = 0;
  info->conn_protocol = 0;

#ifdef USE_SSL
  Curl_ssl_free_certinfo(data);
#endif
  return FETCHE_OK;
}

static FETCHcode getinfo_char(struct Curl_easy *data, FETCHINFO info,
                              const char **param_charp)
{
  switch (info)
  {
  case FETCHINFO_EFFECTIVE_URL:
    *param_charp = data->state.url ? data->state.url : (char *)"";
    break;
  case FETCHINFO_EFFECTIVE_METHOD:
  {
    const char *m = data->set.str[STRING_CUSTOMREQUEST];
    if (!m)
    {
      if (data->set.opt_no_body)
        m = "HEAD";
#ifndef FETCH_DISABLE_HTTP
      else
      {
        switch (data->state.httpreq)
        {
        case HTTPREQ_POST:
        case HTTPREQ_POST_FORM:
        case HTTPREQ_POST_MIME:
          m = "POST";
          break;
        case HTTPREQ_PUT:
          m = "PUT";
          break;
        default: /* this should never happen */
        case HTTPREQ_GET:
          m = "GET";
          break;
        case HTTPREQ_HEAD:
          m = "HEAD";
          break;
        }
      }
#endif
    }
    *param_charp = m;
  }
  break;
  case FETCHINFO_CONTENT_TYPE:
    *param_charp = data->info.contenttype;
    break;
  case FETCHINFO_PRIVATE:
    *param_charp = (char *)data->set.private_data;
    break;
  case FETCHINFO_FTP_ENTRY_PATH:
    /* Return the entrypath string from the most recent connection.
       This pointer was copied from the connectdata structure by FTP.
       The actual string may be free()ed by subsequent libfetch calls so
       it must be copied to a safer area before the next libfetch call.
       Callers must never free it themselves. */
    *param_charp = data->state.most_recent_ftp_entrypath;
    break;
  case FETCHINFO_REDIRECT_URL:
    /* Return the URL this request would have been redirected to if that
       option had been enabled! */
    *param_charp = data->info.wouldredirect;
    break;
  case FETCHINFO_REFERER:
    /* Return the referrer header for this request, or NULL if unset */
    *param_charp = data->state.referer;
    break;
  case FETCHINFO_PRIMARY_IP:
    /* Return the ip address of the most recent (primary) connection */
    *param_charp = data->info.primary.remote_ip;
    break;
  case FETCHINFO_LOCAL_IP:
    /* Return the source/local ip address of the most recent (primary)
       connection */
    *param_charp = data->info.primary.local_ip;
    break;
  case FETCHINFO_RTSP_SESSION_ID:
#ifndef FETCH_DISABLE_RTSP
    *param_charp = data->set.str[STRING_RTSP_SESSION_ID];
#else
    *param_charp = NULL;
#endif
    break;
  case FETCHINFO_SCHEME:
    *param_charp = data->info.conn_scheme;
    break;
  case FETCHINFO_CAPATH:
#ifdef FETCH_CA_PATH
    *param_charp = FETCH_CA_PATH;
#else
    *param_charp = NULL;
#endif
    break;
  case FETCHINFO_CAINFO:
#ifdef FETCH_CA_BUNDLE
    *param_charp = FETCH_CA_BUNDLE;
#else
    *param_charp = NULL;
#endif
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

static FETCHcode getinfo_long(struct Curl_easy *data, FETCHINFO info,
                              long *param_longp)
{
  fetch_socket_t sockfd;

  union
  {
    unsigned long *to_ulong;
    long *to_long;
  } lptr;

#ifdef DEBUGBUILD
  char *timestr = getenv("FETCH_TIME");
  if (timestr)
  {
    unsigned long val = strtoul(timestr, NULL, 10);
    switch (info)
    {
    case FETCHINFO_LOCAL_PORT:
      *param_longp = (long)val;
      return FETCHE_OK;
    default:
      break;
    }
  }
  /* use another variable for this to allow different values */
  timestr = getenv("FETCH_DEBUG_SIZE");
  if (timestr)
  {
    unsigned long val = strtoul(timestr, NULL, 10);
    switch (info)
    {
    case FETCHINFO_HEADER_SIZE:
    case FETCHINFO_REQUEST_SIZE:
      *param_longp = (long)val;
      return FETCHE_OK;
    default:
      break;
    }
  }
#endif

  switch (info)
  {
  case FETCHINFO_RESPONSE_CODE:
    *param_longp = data->info.httpcode;
    break;
  case FETCHINFO_HTTP_CONNECTCODE:
    *param_longp = data->info.httpproxycode;
    break;
  case FETCHINFO_FILETIME:
    if (data->info.filetime > LONG_MAX)
      *param_longp = LONG_MAX;
#if !defined(MSDOS) && !defined(__AMIGA__)
    else if (data->info.filetime < LONG_MIN)
      *param_longp = LONG_MIN;
#endif
    else
      *param_longp = (long)data->info.filetime;
    break;
  case FETCHINFO_HEADER_SIZE:
    *param_longp = (long)data->info.header_size;
    break;
  case FETCHINFO_REQUEST_SIZE:
    *param_longp = (long)data->info.request_size;
    break;
  case FETCHINFO_SSL_VERIFYRESULT:
    *param_longp = data->set.ssl.certverifyresult;
    break;
  case FETCHINFO_PROXY_SSL_VERIFYRESULT:
#ifndef FETCH_DISABLE_PROXY
    *param_longp = data->set.proxy_ssl.certverifyresult;
#else
    *param_longp = 0;
#endif
    break;
  case FETCHINFO_REDIRECT_COUNT:
    *param_longp = data->state.followlocation;
    break;
  case FETCHINFO_HTTPAUTH_AVAIL:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.httpauthavail;
    break;
  case FETCHINFO_PROXYAUTH_AVAIL:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.proxyauthavail;
    break;
  case FETCHINFO_HTTPAUTH_USED:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.httpauthpicked;
    break;
  case FETCHINFO_PROXYAUTH_USED:
    lptr.to_long = param_longp;
    *lptr.to_ulong = data->info.proxyauthpicked;
    break;
  case FETCHINFO_OS_ERRNO:
    *param_longp = data->state.os_errno;
    break;
  case FETCHINFO_NUM_CONNECTS:
    *param_longp = data->info.numconnects;
    break;
  case FETCHINFO_LASTSOCKET:
    sockfd = Curl_getconnectinfo(data, NULL);

    /* note: this is not a good conversion for systems with 64-bit sockets and
       32-bit longs */
    if (sockfd != FETCH_SOCKET_BAD)
      *param_longp = (long)sockfd;
    else
      /* this interface is documented to return -1 in case of badness, which
         may not be the same as the FETCH_SOCKET_BAD value */
      *param_longp = -1;
    break;
  case FETCHINFO_PRIMARY_PORT:
    /* Return the (remote) port of the most recent (primary) connection */
    *param_longp = data->info.primary.remote_port;
    break;
  case FETCHINFO_LOCAL_PORT:
    /* Return the local port of the most recent (primary) connection */
    *param_longp = data->info.primary.local_port;
    break;
  case FETCHINFO_PROXY_ERROR:
    *param_longp = (long)data->info.pxcode;
    break;
  case FETCHINFO_CONDITION_UNMET:
    if (data->info.httpcode == 304)
      *param_longp = 1L;
    else
      /* return if the condition prevented the document to get transferred */
      *param_longp = data->info.timecond ? 1L : 0L;
    break;
#ifndef FETCH_DISABLE_RTSP
  case FETCHINFO_RTSP_CLIENT_CSEQ:
    *param_longp = data->state.rtsp_next_client_CSeq;
    break;
  case FETCHINFO_RTSP_SERVER_CSEQ:
    *param_longp = data->state.rtsp_next_server_CSeq;
    break;
  case FETCHINFO_RTSP_CSEQ_RECV:
    *param_longp = data->state.rtsp_CSeq_recv;
    break;
#else
  case FETCHINFO_RTSP_CLIENT_CSEQ:
  case FETCHINFO_RTSP_SERVER_CSEQ:
  case FETCHINFO_RTSP_CSEQ_RECV:
    *param_longp = 0;
    break;
#endif
  case FETCHINFO_HTTP_VERSION:
    switch (data->info.httpversion)
    {
    case 10:
      *param_longp = FETCH_HTTP_VERSION_1_0;
      break;
    case 11:
      *param_longp = FETCH_HTTP_VERSION_1_1;
      break;
    case 20:
      *param_longp = FETCH_HTTP_VERSION_2_0;
      break;
    case 30:
      *param_longp = FETCH_HTTP_VERSION_3;
      break;
    default:
      *param_longp = FETCH_HTTP_VERSION_NONE;
      break;
    }
    break;
  case FETCHINFO_PROTOCOL:
    *param_longp = (long)data->info.conn_protocol;
    break;
  case FETCHINFO_USED_PROXY:
    *param_longp =
#ifdef FETCH_DISABLE_PROXY
        0
#else
        data->info.used_proxy
#endif
        ;
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

#define DOUBLE_SECS(x) (double)(x) / 1000000

static FETCHcode getinfo_offt(struct Curl_easy *data, FETCHINFO info,
                              fetch_off_t *param_offt)
{
#ifdef DEBUGBUILD
  char *timestr = getenv("FETCH_TIME");
  if (timestr)
  {
    unsigned long val = strtoul(timestr, NULL, 10);
    switch (info)
    {
    case FETCHINFO_TOTAL_TIME_T:
    case FETCHINFO_NAMELOOKUP_TIME_T:
    case FETCHINFO_CONNECT_TIME_T:
    case FETCHINFO_APPCONNECT_TIME_T:
    case FETCHINFO_PRETRANSFER_TIME_T:
    case FETCHINFO_POSTTRANSFER_TIME_T:
    case FETCHINFO_QUEUE_TIME_T:
    case FETCHINFO_STARTTRANSFER_TIME_T:
    case FETCHINFO_REDIRECT_TIME_T:
    case FETCHINFO_SPEED_DOWNLOAD_T:
    case FETCHINFO_SPEED_UPLOAD_T:
      *param_offt = (fetch_off_t)val;
      return FETCHE_OK;
    default:
      break;
    }
  }
#endif
  switch (info)
  {
  case FETCHINFO_FILETIME_T:
    *param_offt = (fetch_off_t)data->info.filetime;
    break;
  case FETCHINFO_SIZE_UPLOAD_T:
    *param_offt = data->progress.ul.cur_size;
    break;
  case FETCHINFO_SIZE_DOWNLOAD_T:
    *param_offt = data->progress.dl.cur_size;
    break;
  case FETCHINFO_SPEED_DOWNLOAD_T:
    *param_offt = data->progress.dl.speed;
    break;
  case FETCHINFO_SPEED_UPLOAD_T:
    *param_offt = data->progress.ul.speed;
    break;
  case FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T:
    *param_offt = (data->progress.flags & PGRS_DL_SIZE_KNOWN) ? data->progress.dl.total_size : -1;
    break;
  case FETCHINFO_CONTENT_LENGTH_UPLOAD_T:
    *param_offt = (data->progress.flags & PGRS_UL_SIZE_KNOWN) ? data->progress.ul.total_size : -1;
    break;
  case FETCHINFO_TOTAL_TIME_T:
    *param_offt = data->progress.timespent;
    break;
  case FETCHINFO_NAMELOOKUP_TIME_T:
    *param_offt = data->progress.t_nslookup;
    break;
  case FETCHINFO_CONNECT_TIME_T:
    *param_offt = data->progress.t_connect;
    break;
  case FETCHINFO_APPCONNECT_TIME_T:
    *param_offt = data->progress.t_appconnect;
    break;
  case FETCHINFO_PRETRANSFER_TIME_T:
    *param_offt = data->progress.t_pretransfer;
    break;
  case FETCHINFO_POSTTRANSFER_TIME_T:
    *param_offt = data->progress.t_posttransfer;
    break;
  case FETCHINFO_STARTTRANSFER_TIME_T:
    *param_offt = data->progress.t_starttransfer;
    break;
  case FETCHINFO_QUEUE_TIME_T:
    *param_offt = data->progress.t_postqueue;
    break;
  case FETCHINFO_REDIRECT_TIME_T:
    *param_offt = data->progress.t_redirect;
    break;
  case FETCHINFO_RETRY_AFTER:
    *param_offt = data->info.retry_after;
    break;
  case FETCHINFO_XFER_ID:
    *param_offt = data->id;
    break;
  case FETCHINFO_CONN_ID:
    *param_offt = data->conn ? data->conn->connection_id : data->state.recent_conn_id;
    break;
  case FETCHINFO_EARLYDATA_SENT_T:
    *param_offt = data->progress.earlydata_sent;
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

static FETCHcode getinfo_double(struct Curl_easy *data, FETCHINFO info,
                                double *param_doublep)
{
#ifdef DEBUGBUILD
  char *timestr = getenv("FETCH_TIME");
  if (timestr)
  {
    unsigned long val = strtoul(timestr, NULL, 10);
    switch (info)
    {
    case FETCHINFO_TOTAL_TIME:
    case FETCHINFO_NAMELOOKUP_TIME:
    case FETCHINFO_CONNECT_TIME:
    case FETCHINFO_APPCONNECT_TIME:
    case FETCHINFO_PRETRANSFER_TIME:
    case FETCHINFO_STARTTRANSFER_TIME:
    case FETCHINFO_REDIRECT_TIME:
    case FETCHINFO_SPEED_DOWNLOAD:
    case FETCHINFO_SPEED_UPLOAD:
      *param_doublep = (double)val;
      return FETCHE_OK;
    default:
      break;
    }
  }
#endif
  switch (info)
  {
  case FETCHINFO_TOTAL_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.timespent);
    break;
  case FETCHINFO_NAMELOOKUP_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_nslookup);
    break;
  case FETCHINFO_CONNECT_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_connect);
    break;
  case FETCHINFO_APPCONNECT_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_appconnect);
    break;
  case FETCHINFO_PRETRANSFER_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_pretransfer);
    break;
  case FETCHINFO_STARTTRANSFER_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_starttransfer);
    break;
  case FETCHINFO_SIZE_UPLOAD:
    *param_doublep = (double)data->progress.ul.cur_size;
    break;
  case FETCHINFO_SIZE_DOWNLOAD:
    *param_doublep = (double)data->progress.dl.cur_size;
    break;
  case FETCHINFO_SPEED_DOWNLOAD:
    *param_doublep = (double)data->progress.dl.speed;
    break;
  case FETCHINFO_SPEED_UPLOAD:
    *param_doublep = (double)data->progress.ul.speed;
    break;
  case FETCHINFO_CONTENT_LENGTH_DOWNLOAD:
    *param_doublep = (data->progress.flags & PGRS_DL_SIZE_KNOWN) ? (double)data->progress.dl.total_size : -1;
    break;
  case FETCHINFO_CONTENT_LENGTH_UPLOAD:
    *param_doublep = (data->progress.flags & PGRS_UL_SIZE_KNOWN) ? (double)data->progress.ul.total_size : -1;
    break;
  case FETCHINFO_REDIRECT_TIME:
    *param_doublep = DOUBLE_SECS(data->progress.t_redirect);
    break;

  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

static FETCHcode getinfo_slist(struct Curl_easy *data, FETCHINFO info,
                               struct fetch_slist **param_slistp)
{
  union
  {
    struct fetch_certinfo *to_certinfo;
    struct fetch_slist *to_slist;
  } ptr;

  switch (info)
  {
  case FETCHINFO_SSL_ENGINES:
    *param_slistp = Curl_ssl_engines_list(data);
    break;
  case FETCHINFO_COOKIELIST:
    *param_slistp = Curl_cookie_list(data);
    break;
  case FETCHINFO_CERTINFO:
    /* Return the a pointer to the certinfo struct. Not really an slist
       pointer but we can pretend it is here */
    ptr.to_certinfo = &data->info.certs;
    *param_slistp = ptr.to_slist;
    break;
  case FETCHINFO_TLS_SESSION:
  case FETCHINFO_TLS_SSL_PTR:
  {
    struct fetch_tlssessioninfo **tsip = (struct fetch_tlssessioninfo **)
        param_slistp;
    struct fetch_tlssessioninfo *tsi = &data->tsi;
#ifdef USE_SSL
    struct connectdata *conn = data->conn;
#endif

    *tsip = tsi;
    tsi->backend = Curl_ssl_backend();
    tsi->internals = NULL;

#ifdef USE_SSL
    if (conn && tsi->backend != FETCHSSLBACKEND_NONE)
    {
      tsi->internals = Curl_ssl_get_internals(data, FIRSTSOCKET, info, 0);
    }
#endif
  }
  break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

static FETCHcode getinfo_socket(struct Curl_easy *data, FETCHINFO info,
                                fetch_socket_t *param_socketp)
{
  switch (info)
  {
  case FETCHINFO_ACTIVESOCKET:
    *param_socketp = Curl_getconnectinfo(data, NULL);
    break;
  default:
    return FETCHE_UNKNOWN_OPTION;
  }

  return FETCHE_OK;
}

FETCHcode Curl_getinfo(struct Curl_easy *data, FETCHINFO info, ...)
{
  va_list arg;
  long *param_longp = NULL;
  double *param_doublep = NULL;
  fetch_off_t *param_offt = NULL;
  const char **param_charp = NULL;
  struct fetch_slist **param_slistp = NULL;
  fetch_socket_t *param_socketp = NULL;
  int type;
  FETCHcode result = FETCHE_UNKNOWN_OPTION;

  if (!data)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, info);

  type = FETCHINFO_TYPEMASK & (int)info;
  switch (type)
  {
  case FETCHINFO_STRING:
    param_charp = va_arg(arg, const char **);
    if (param_charp)
      result = getinfo_char(data, info, param_charp);
    break;
  case FETCHINFO_LONG:
    param_longp = va_arg(arg, long *);
    if (param_longp)
      result = getinfo_long(data, info, param_longp);
    break;
  case FETCHINFO_DOUBLE:
    param_doublep = va_arg(arg, double *);
    if (param_doublep)
      result = getinfo_double(data, info, param_doublep);
    break;
  case FETCHINFO_OFF_T:
    param_offt = va_arg(arg, fetch_off_t *);
    if (param_offt)
      result = getinfo_offt(data, info, param_offt);
    break;
  case FETCHINFO_SLIST:
    param_slistp = va_arg(arg, struct fetch_slist **);
    if (param_slistp)
      result = getinfo_slist(data, info, param_slistp);
    break;
  case FETCHINFO_SOCKET:
    param_socketp = va_arg(arg, fetch_socket_t *);
    if (param_socketp)
      result = getinfo_socket(data, info, param_socketp);
    break;
  default:
    break;
  }

  va_end(arg);

  return result;
}
