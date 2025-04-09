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
#include "strparse.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static void trc_write(struct Curl_easy *data, curl_infotype type,
                      const char *ptr, size_t size)
{
  if(data->set.verbose) {
    if(data->set.fdebug) {
      bool inCallback = Curl_is_in_callback(data);
      Curl_set_in_callback(data, TRUE);
      (void)(*data->set.fdebug)(data, type, CURL_UNCONST(ptr), size,
                                data->set.debugdata);
      Curl_set_in_callback(data, inCallback);
    }
    else {
      static const char s_infotype[CURLINFO_END][3] = {
        "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
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

/* max length we trace before ending in '...' */
#define TRC_LINE_MAX 2048

#define CURL_TRC_FMT_IDSC   "[x-%" CURL_FORMAT_CURL_OFF_T "] "
#define CURL_TRC_FMT_IDSD   "[%" CURL_FORMAT_CURL_OFF_T "-x] "
#define CURL_TRC_FMT_IDSDC  "[%" CURL_FORMAT_CURL_OFF_T "-%" \
                            CURL_FORMAT_CURL_OFF_T "] "

static struct curl_trc_feat Curl_trc_feat_ids = {
  "LIB-IDS",
  CURL_LOG_LVL_NONE,
};
#define CURL_TRC_IDS(data) \
             (Curl_trc_is_verbose(data) && \
             Curl_trc_feat_ids.log_level >= CURL_LOG_LVL_INFO)

static size_t trc_print_ids(struct Curl_easy *data, char *buf, size_t maxlen)
{
  curl_off_t cid = data->conn ?
                   data->conn->connection_id : data->state.recent_conn_id;
  if(data->id >= 0) {
    if(cid >= 0)
      return msnprintf(buf, maxlen, CURL_TRC_FMT_IDSDC, data->id, cid);
    else
      return msnprintf(buf, maxlen, CURL_TRC_FMT_IDSD, data->id);
  }
  else if(cid >= 0)
    return msnprintf(buf, maxlen, CURL_TRC_FMT_IDSC, cid);
  else {
    return msnprintf(buf, maxlen, "[x-x] ");
  }
}

static size_t trc_end_buf(char *buf, size_t len, size_t maxlen, bool addnl)
{
  /* make sure we end the trace line in `buf` properly. It needs
   * to end with a terminating '\0' or '\n\0' */
  if(len >= (maxlen - (addnl ? 2 : 1))) {
    len = maxlen - 5;
    buf[len++] = '.';
    buf[len++] = '.';
    buf[len++] = '.';
    buf[len++] = '\n';
  }
  else if(addnl)
    buf[len++] = '\n';
  buf[len] = '\0';
  return len;
}

void Curl_debug(struct Curl_easy *data, curl_infotype type,
                const char *ptr, size_t size)
{
  if(data->set.verbose) {
    static const char s_infotype[CURLINFO_END][3] = {
      "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    char buf[TRC_LINE_MAX];
    size_t len;
    if(data->set.fdebug) {
      bool inCallback = Curl_is_in_callback(data);

      if(CURL_TRC_IDS(data) && (size < TRC_LINE_MAX)) {
        len = trc_print_ids(data, buf, TRC_LINE_MAX);
        len += msnprintf(buf + len, TRC_LINE_MAX - len, "%.*s",
                         (int)size, ptr);
        len = trc_end_buf(buf, len, TRC_LINE_MAX, FALSE);
        Curl_set_in_callback(data, TRUE);
        (void)(*data->set.fdebug)(data, type, buf, len, data->set.debugdata);
        Curl_set_in_callback(data, inCallback);
      }
      else {
        Curl_set_in_callback(data, TRUE);
        (void)(*data->set.fdebug)(data, type, CURL_UNCONST(ptr),
                                  size, data->set.debugdata);
        Curl_set_in_callback(data, inCallback);
      }
    }
    else {
      switch(type) {
      case CURLINFO_TEXT:
      case CURLINFO_HEADER_OUT:
      case CURLINFO_HEADER_IN:
        if(CURL_TRC_IDS(data)) {
          len = trc_print_ids(data, buf, TRC_LINE_MAX);
          fwrite(buf, len, 1, data->set.err);
        }
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
    size_t len;
    char error[CURL_ERROR_SIZE + 2];
    va_start(ap, fmt);
    len = mvsnprintf(error, CURL_ERROR_SIZE, fmt, ap);

    if(data->set.errorbuffer && !data->state.errorbuf) {
      strcpy(data->set.errorbuffer, error);
      data->state.errorbuf = TRUE; /* wrote error string */
    }
    error[len++] = '\n';
    error[len] = '\0';
    trc_write(data, CURLINFO_TEXT, error, len);
    va_end(ap);
  }
}

#if !defined(CURL_DISABLE_VERBOSE_STRINGS)


static void trc_infof(struct Curl_easy *data,
                      struct curl_trc_feat *feat,
                      const char *opt_id, int opt_id_idx,
                      const char * const fmt, va_list ap)  CURL_PRINTF(5, 0);

static void trc_infof(struct Curl_easy *data,
                      struct curl_trc_feat *feat,
                      const char *opt_id, int opt_id_idx,
                      const char * const fmt, va_list ap)
{
  size_t len = 0;
  char buf[TRC_LINE_MAX];

  if(CURL_TRC_IDS(data))
    len += trc_print_ids(data, buf + len, TRC_LINE_MAX - len);
  if(feat)
    len += msnprintf(buf + len, TRC_LINE_MAX - len, "[%s] ", feat->name);
  if(opt_id) {
    if(opt_id_idx > 0)
      len += msnprintf(buf + len, TRC_LINE_MAX - len, "[%s-%d] ",
                       opt_id, opt_id_idx);
    else
      len += msnprintf(buf + len, TRC_LINE_MAX - len, "[%s] ", opt_id);
  }
  len += mvsnprintf(buf + len, TRC_LINE_MAX - len, fmt, ap);
  len = trc_end_buf(buf, len, TRC_LINE_MAX, TRUE);
  trc_write(data, CURLINFO_TEXT, buf, len);
}

void Curl_infof(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_is_verbose(data)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, data->state.feat, NULL, 0, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_cf_infof(struct Curl_easy *data, const struct Curl_cfilter *cf,
                       const char *fmt, ...)
{
  DEBUGASSERT(cf);
  if(Curl_trc_cf_is_verbose(cf, data)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, data->state.feat, cf->cft->name, cf->sockindex, fmt, ap);
    va_end(ap);
  }
}

struct curl_trc_feat Curl_trc_feat_multi = {
  "MULTI",
  CURL_LOG_LVL_NONE,
};
struct curl_trc_feat Curl_trc_feat_read = {
  "READ",
  CURL_LOG_LVL_NONE,
};
struct curl_trc_feat Curl_trc_feat_write = {
  "WRITE",
  CURL_LOG_LVL_NONE,
};
struct curl_trc_feat Curl_trc_feat_dns = {
  "DNS",
  CURL_LOG_LVL_NONE,
};


static const char * const Curl_trc_mstate_names[]={
  "INIT",
  "PENDING",
  "SETUP",
  "CONNECT",
  "RESOLVING",
  "CONNECTING",
  "TUNNELING",
  "PROTOCONNECT",
  "PROTOCONNECTING",
  "DO",
  "DOING",
  "DOING_MORE",
  "DID",
  "PERFORMING",
  "RATELIMITING",
  "DONE",
  "COMPLETED",
  "MSGSENT",
};

const char *Curl_trc_mstate_name(int state)
{
  if((state >= 0) && ((size_t)state < CURL_ARRAYSIZE(Curl_trc_mstate_names)))
    return Curl_trc_mstate_names[(size_t)state];
  return "?";
}

void Curl_trc_multi(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_multi)) {
    const char *sname = (data->id >= 0) ?
                        Curl_trc_mstate_name(data->mstate) : NULL;
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_multi, sname, 0, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_read(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_read)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_read, NULL, 0, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_write(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_write)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_write, NULL, 0, fmt, ap);
    va_end(ap);
  }
}

void Curl_trc_dns(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_dns, NULL, 0, fmt, ap);
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
    trc_infof(data, &Curl_trc_feat_ftp, NULL, 0, fmt, ap);
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
    trc_infof(data, &Curl_trc_feat_smtp, NULL, 0, fmt, ap);
    va_end(ap);
  }
}
#endif /* !CURL_DISABLE_SMTP */

#ifdef USE_SSL
struct curl_trc_feat Curl_trc_feat_ssls = {
  "SSLS",
  CURL_LOG_LVL_NONE,
};

void Curl_trc_ssls(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ssls)) {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Curl_trc_feat_ssls, NULL, 0, fmt, ap);
    va_end(ap);
  }
}
#endif /* USE_SSL */

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
    trc_infof(data, &Curl_trc_feat_ws, NULL, 0, fmt, ap);
    va_end(ap);
  }
}
#endif /* !CURL_DISABLE_WEBSOCKETS && !CURL_DISABLE_HTTP */

#define TRC_CT_NONE        (0)
#define TRC_CT_PROTOCOL    (1<<(0))
#define TRC_CT_NETWORK     (1<<(1))
#define TRC_CT_PROXY       (1<<(2))
#define TRC_CT_INTERNALS   (1<<(3))

struct trc_feat_def {
  struct curl_trc_feat *feat;
  unsigned int category;
};

static struct trc_feat_def trc_feats[] = {
  { &Curl_trc_feat_ids,       TRC_CT_INTERNALS },
  { &Curl_trc_feat_multi,     TRC_CT_NETWORK },
  { &Curl_trc_feat_read,      TRC_CT_NONE },
  { &Curl_trc_feat_write,     TRC_CT_NONE },
  { &Curl_trc_feat_dns,       TRC_CT_NETWORK },
#ifndef CURL_DISABLE_FTP
  { &Curl_trc_feat_ftp,       TRC_CT_PROTOCOL },
#endif
#ifndef CURL_DISABLE_DOH
#endif
#ifndef CURL_DISABLE_SMTP
  { &Curl_trc_feat_smtp,      TRC_CT_PROTOCOL },
#endif
#ifdef USE_SSL
  { &Curl_trc_feat_ssls,      TRC_CT_NETWORK },
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
#if !defined(CURL_DISABLE_HTTP)
  { &Curl_cft_http_connect,   TRC_CT_PROTOCOL },
#endif
};

static void trc_apply_level_by_name(struct Curl_str *token, int lvl)
{
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(trc_cfts); ++i) {
    if(Curl_str_casecompare(token, trc_cfts[i].cft->name)) {
      trc_cfts[i].cft->log_level = lvl;
      break;
    }
  }
  for(i = 0; i < CURL_ARRAYSIZE(trc_feats); ++i) {
    if(Curl_str_casecompare(token, trc_feats[i].feat->name)) {
      trc_feats[i].feat->log_level = lvl;
      break;
    }
  }
}

static void trc_apply_level_by_category(int category, int lvl)
{
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(trc_cfts); ++i) {
    if(!category || (trc_cfts[i].category & category))
      trc_cfts[i].cft->log_level = lvl;
  }
  for(i = 0; i < CURL_ARRAYSIZE(trc_feats); ++i) {
    if(!category || (trc_feats[i].category & category))
      trc_feats[i].feat->log_level = lvl;
  }
}

static CURLcode trc_opt(const char *config)
{
  struct Curl_str out;
  while(!Curl_str_until(&config, &out, 32, ',')) {
    int lvl = CURL_LOG_LVL_INFO;
    const char *token = Curl_str(&out);

    if(*token == '-') {
      lvl = CURL_LOG_LVL_NONE;
      Curl_str_nudge(&out, 1);
    }
    else if(*token == '+')
      Curl_str_nudge(&out, 1);

    if(Curl_str_casecompare(&out, "all"))
      trc_apply_level_by_category(TRC_CT_NONE, lvl);
    else if(Curl_str_casecompare(&out, "protocol"))
      trc_apply_level_by_category(TRC_CT_PROTOCOL, lvl);
    else if(Curl_str_casecompare(&out, "network"))
      trc_apply_level_by_category(TRC_CT_NETWORK, lvl);
    else if(Curl_str_casecompare(&out, "proxy"))
      trc_apply_level_by_category(TRC_CT_PROXY, lvl);
    else if(Curl_str_casecompare(&out, "doh")) {
      struct Curl_str dns = { "dns", 3 };
      trc_apply_level_by_name(&dns, lvl);
    }
    else
      trc_apply_level_by_name(&out, lvl);

    if(Curl_str_single(&config, ','))
      break;
  }
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

void Curl_infof(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

void Curl_trc_cf_infof(struct Curl_easy *data, const struct Curl_cfilter *cf,
                       const char *fmt, ...)
{
  (void)data; (void)cf; (void)fmt;
}

struct curl_trc_feat;

void Curl_trc_multi(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

void Curl_trc_write(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

void Curl_trc_dns(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

void Curl_trc_read(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

#ifndef CURL_DISABLE_FTP
void Curl_trc_ftp(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}
#endif
#ifndef CURL_DISABLE_SMTP
void Curl_trc_smtp(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}
#endif
#if !defined(CURL_DISABLE_WEBSOCKETS) || !defined(CURL_DISABLE_HTTP)
void Curl_trc_ws(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}
#endif

void Curl_trc_ssls(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}

#endif /* !defined(CURL_DISABLE_VERBOSE_STRINGS) */
