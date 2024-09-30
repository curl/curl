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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "curl_trc.h"
#include "urldata.h"
#include "easyif.h"
#include "cfilters.h"
#include "timeval.h"
#include "multiif.h"
#include "strcase.h"

#include "cf-socket.h"
#include "connect.h"
#include "doh.h"
#include "http2.h"
#include "http_proxy.h"
#include "cf-h1-proxy.h"
#include "cf-h2-proxy.h"
#include "cf-haproxy.h"
#include "cf-https-connect.h"
#include "socks.h"
#include "strtok.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

void Curl_debug(struct Curl_easy *data, curl_infotype type,
                char *ptr, size_t size)
{
  if(data->set.verbose) {
    static const char s_infotype[CURLINFO_END][3] = {
      "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    if(data->set.fdebug) {
      bool inCallback = Curl_is_in_callback(data);
      Curl_set_in_callback(data, true);
      (void)(*data->set.fdebug)(data, type, ptr, size, data->set.debugdata);
      Curl_set_in_callback(data, inCallback);
    }
    else {
      switch(type) {
      case CURLINFO_TEXT:
      case CURLINFO_HEADER_OUT:
      case CURLINFO_HEADER_IN:
        fwrite(s_infotype[type], 2, 1, data->set.err);
        fwrite(ptr, size, 1, data->set.err);
        break;
      default: /* nada */
        break;
      }
    }
  }
}


/* Curl_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */
void Curl_failf(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(data->set.verbose || data->set.errorbuffer) {
    va_list ap;
    int len;
    char error[CURL_ERROR_SIZE + 2];
    va_start(ap, fmt);
    len = mvsnprintf(error, CURL_ERROR_SIZE, fmt, ap);

    if(data->set.errorbuffer && !data->state.errorbuf) {
      strcpy(data->set.errorbuffer, error);
      data->state.errorbuf = TRUE; /* wrote error string */
    }
    error[len++] = '\n';
    error[len] = '\0';
    Curl_debug(data, CURLINFO_TEXT, error, len);
    va_end(ap);
  }
}

#if !defined(CURL_DISABLE_VERBOSE_STRINGS)

/* Curl_infof() is for info message along the way */
#define MAXINFO 2048

static void trc_infof(struct Curl_easy *data, struct curl_trc_feat *feat,
                      const char * const fmt, va_list ap)  CURL_PRINTF(3, 0);

static void trc_infof(struct Curl_easy *data, struct curl_trc_feat *feat,
                      const char * const fmt, va_list ap)
{
  int len = 0;
  char buffer[MAXINFO + 5];
  if(feat)
    len = msnprintf(buffer, (MAXINFO + 1), "[%s] ", feat->name);
  len += mvsnprintf(buffer + len, (MAXINFO + 1) - len, fmt, ap);
  if(len >= MAXINFO) { /* too long, shorten with '...' */
    --len;
    buffer[len++] = '.';
    buffer[len++] = '.';
    buffer[len++] = '.';
  }
  buffer[len++] = '\n';
  buffer[len] = '\0';
  Curl_debug(data, CURLINFO_TEXT, buffer, len);
}

void Curl_infof(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_is_verbose(data)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, data->state.feat, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_cf_infof(struct Curl_easy *data, struct Curl_cfilter *cf,
                       const char *fmt, ...)
{
  DEBUGASSERT(cf);
  if(Curl_trc_cf_is_verbose(cf, data)) {
    va_list ap;
    int len = 0;
    char buffer[MAXINFO + 2];
    if(data->state.feat)
      len += msnprintf(buffer + len, MAXINFO - len, "[%s] ",
                       data->state.feat->name);
    if(cf->sockindex)
      len += msnprintf(buffer + len, MAXINFO - len, "[%s-%d] ",
                      cf->cft->name, cf->sockindex);
    else
      len += msnprintf(buffer + len, MAXINFO - len, "[%s] ", cf->cft->name);
    va_start(ap, fmt);
    len += mvsnprintf(buffer + len, MAXINFO - len, fmt, ap);
    va_end(ap);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    Curl_debug(data, CURLINFO_TEXT, buffer, len);
  }
}

struct curl_trc_feat Curl_trc_feat_read = {
  "READ",
  CURL_LOG_LVL_NONE,
};
struct curl_trc_feat Curl_trc_feat_write = {
  "WRITE",
  CURL_LOG_LVL_NONE,
};

void Curl_trc_read(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_read)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_read, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_write(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_write)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_write, fmt, ap);
    va_end(ap);
  }
}

#ifndef CURL_DISABLE_FTP
struct curl_trc_feat Curl_trc_feat_ftp = {
  "FTP",
  CURL_LOG_LVL_NONE,
};

void Curl_trc_ftp(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ftp)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_ftp, fmt, ap);
    va_end(ap);
  }
}
#endif /* !CURL_DISABLE_FTP */

#ifndef CURL_DISABLE_SMTP
struct curl_trc_feat Curl_trc_feat_smtp = {
  "SMTP",
  CURL_LOG_LVL_NONE,
};

void Curl_trc_smtp(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_smtp)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_smtp, fmt, ap);
    va_end(ap);
  }
}
#endif /* !CURL_DISABLE_SMTP */

#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)
struct curl_trc_feat Curl_trc_feat_ws = {
  "WS",
  CURL_LOG_LVL_NONE,
};

void Curl_trc_ws(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ws)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_ws, fmt, ap);
    va_end(ap);
  }
}
#endif /* !CURL_DISABLE_WEBSOCKETS && !CURL_DISABLE_HTTP */

#define TRC_CT_NONE        (0)
#define TRC_CT_PROTOCOL    (1<<(0))
#define TRC_CT_NETWORK     (1<<(1))
#define TRC_CT_PROXY       (1<<(2))

struct trc_feat_def {
  struct curl_trc_feat *feat;
  unsigned int category;
};

static struct trc_feat_def trc_feats[] = {
  { &Curl_trc_feat_read,      TRC_CT_NONE },
  { &Curl_trc_feat_write,     TRC_CT_NONE },
#ifndef CURL_DISABLE_FTP
  { &Curl_trc_feat_ftp,       TRC_CT_PROTOCOL },
#endif
#ifndef CURL_DISABLE_DOH
  { &Curl_doh_trc,            TRC_CT_NETWORK },
#endif
#ifndef CURL_DISABLE_SMTP
  { &Curl_trc_feat_smtp,      TRC_CT_PROTOCOL },
#endif
#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)
  { &Curl_trc_feat_ws,        TRC_CT_PROTOCOL },
#endif
};

struct trc_cft_def {
  struct Curl_cftype *cft;
  unsigned int category;
};

static struct trc_cft_def trc_cfts[] = {
  { &Curl_cft_tcp,            TRC_CT_NETWORK },
  { &Curl_cft_udp,            TRC_CT_NETWORK },
  { &Curl_cft_unix,           TRC_CT_NETWORK },
  { &Curl_cft_tcp_accept,     TRC_CT_NETWORK },
  { &Curl_cft_happy_eyeballs, TRC_CT_NETWORK },
  { &Curl_cft_setup,          TRC_CT_PROTOCOL },
#ifdef USE_NGHTTP2
  { &Curl_cft_nghttp2,        TRC_CT_PROTOCOL },
#endif
#ifdef USE_SSL
  { &Curl_cft_ssl,            TRC_CT_NETWORK },
#ifndef CURL_DISABLE_PROXY
  { &Curl_cft_ssl_proxy,      TRC_CT_PROXY },
#endif
#endif
#if !defined(CURL_DISABLE_PROXY)
#if !defined(CURL_DISABLE_HTTP)
  { &Curl_cft_h1_proxy,       TRC_CT_PROXY },
#ifdef USE_NGHTTP2
  { &Curl_cft_h2_proxy,       TRC_CT_PROXY },
#endif
  { &Curl_cft_http_proxy,     TRC_CT_PROXY },
#endif /* !CURL_DISABLE_HTTP */
  { &Curl_cft_haproxy,        TRC_CT_PROXY },
  { &Curl_cft_socks_proxy,    TRC_CT_PROXY },
#endif /* !CURL_DISABLE_PROXY */
#ifdef USE_HTTP3
  { &Curl_cft_http3,          TRC_CT_PROTOCOL },
#endif
#if !defined(CURL_DISABLE_HTTP) && !defined(USE_HYPER)
  { &Curl_cft_http_connect,   TRC_CT_PROTOCOL },
#endif
};

static void trc_apply_level_by_name(const char * const token, int lvl)
{
  size_t i;

  for(i = 0; i < ARRAYSIZE(trc_cfts); ++i) {
    if(strcasecompare(token, trc_cfts[i].cft->name)) {
      trc_cfts[i].cft->log_level = lvl;
      break;
    }
  }
  for(i = 0; i < ARRAYSIZE(trc_feats); ++i) {
    if(strcasecompare(token, trc_feats[i].feat->name)) {
      trc_feats[i].feat->log_level = lvl;
      break;
    }
  }
}

static void trc_apply_level_by_category(int category, int lvl)
{
  size_t i;

  for(i = 0; i < ARRAYSIZE(trc_cfts); ++i) {
    if(!category || (trc_cfts[i].category & category))
      trc_cfts[i].cft->log_level = lvl;
  }
  for(i = 0; i < ARRAYSIZE(trc_feats); ++i) {
    if(!category || (trc_feats[i].category & category))
      trc_feats[i].feat->log_level = lvl;
  }
}

static CURLcode trc_opt(const char *config)
{
  char *token, *tok_buf, *tmp;
  int lvl;

  tmp = strdup(config);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  token = strtok_r(tmp, ", ", &tok_buf);
  while(token) {
    switch(*token) {
      case '-':
        lvl = CURL_LOG_LVL_NONE;
        ++token;
        break;
      case '+':
        lvl = CURL_LOG_LVL_INFO;
        ++token;
        break;
      default:
        lvl = CURL_LOG_LVL_INFO;
        break;
    }
    if(strcasecompare(token, "all"))
      trc_apply_level_by_category(TRC_CT_NONE, lvl);
    else if(strcasecompare(token, "protocol"))
      trc_apply_level_by_category(TRC_CT_PROTOCOL, lvl);
    else if(strcasecompare(token, "network"))
      trc_apply_level_by_category(TRC_CT_NETWORK, lvl);
    else if(strcasecompare(token, "proxy"))
      trc_apply_level_by_category(TRC_CT_PROXY, lvl);
    else
      trc_apply_level_by_name(token, lvl);

    token = strtok_r(NULL, ", ", &tok_buf);
  }
  free(tmp);
  return CURLE_OK;
}

CURLcode Curl_trc_opt(const char *config)
{
  CURLcode result = config ? trc_opt(config) : CURLE_OK;
#ifdef DEBUGBUILD
  /* CURL_DEBUG can override anything */
  if(!result) {
    const char *dbg_config = getenv("CURL_DEBUG");
    if(dbg_config)
      result = trc_opt(dbg_config);
  }
#endif /* DEBUGBUILD */
  return result;
}

CURLcode Curl_trc_init(void)
{
#ifdef DEBUGBUILD
  return Curl_trc_opt(NULL);
#else
  return CURLE_OK;
#endif
}

#else /* defined(CURL_DISABLE_VERBOSE_STRINGS) */

CURLcode Curl_trc_init(void)
{
  return CURLE_OK;
}

#endif /* !defined(CURL_DISABLE_VERBOSE_STRINGS) */
