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
 * are also available at https://fetch.se/docs/copyright.html.
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

#include "fetch_trc.h"
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
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

void Fetch_debug(struct Fetch_easy *data, fetch_infotype type,
                char *ptr, size_t size)
{
  if (data->set.verbose)
  {
    static const char s_infotype[FETCHINFO_END][3] = {
        "* ", "< ", "> ", "{ ", "} ", "{ ", "} "};
    if (data->set.fdebug)
    {
      bool inCallback = Fetch_is_in_callback(data);
      Fetch_set_in_callback(data, TRUE);
      (void)(*data->set.fdebug)(data, type, ptr, size, data->set.debugdata);
      Fetch_set_in_callback(data, inCallback);
    }
    else
    {
      switch (type)
      {
      case FETCHINFO_TEXT:
      case FETCHINFO_HEADER_OUT:
      case FETCHINFO_HEADER_IN:
        fwrite(s_infotype[type], 2, 1, data->set.err);
        fwrite(ptr, size, 1, data->set.err);
        break;
      default: /* nada */
        break;
      }
    }
  }
}

/* Fetch_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */
void Fetch_failf(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (data->set.verbose || data->set.errorbuffer)
  {
    va_list ap;
    int len;
    char error[FETCH_ERROR_SIZE + 2];
    va_start(ap, fmt);
    len = mvsnprintf(error, FETCH_ERROR_SIZE, fmt, ap);

    if (data->set.errorbuffer && !data->state.errorbuf)
    {
      strcpy(data->set.errorbuffer, error);
      data->state.errorbuf = TRUE; /* wrote error string */
    }
    error[len++] = '\n';
    error[len] = '\0';
    Fetch_debug(data, FETCHINFO_TEXT, error, len);
    va_end(ap);
  }
}

#if !defined(FETCH_DISABLE_VERBOSE_STRINGS)

/* Fetch_infof() is for info message along the way */
#define MAXINFO 2048

static void trc_infof(struct Fetch_easy *data, struct fetch_trc_feat *feat,
                      const char *const fmt, va_list ap) FETCH_PRINTF(3, 0);

static void trc_infof(struct Fetch_easy *data, struct fetch_trc_feat *feat,
                      const char *const fmt, va_list ap)
{
  int len = 0;
  char buffer[MAXINFO + 5];
  if (feat)
    len = msnprintf(buffer, (MAXINFO + 1), "[%s] ", feat->name);
  len += mvsnprintf(buffer + len, (MAXINFO + 1) - len, fmt, ap);
  if (len >= MAXINFO)
  { /* too long, shorten with '...' */
    --len;
    buffer[len++] = '.';
    buffer[len++] = '.';
    buffer[len++] = '.';
  }
  buffer[len++] = '\n';
  buffer[len] = '\0';
  Fetch_debug(data, FETCHINFO_TEXT, buffer, len);
}

void Fetch_infof(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_is_verbose(data))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, data->state.feat, fmt, ap);
    va_end(ap);
  }
}

void Fetch_trc_cf_infof(struct Fetch_easy *data, struct Fetch_cfilter *cf,
                       const char *fmt, ...)
{
  DEBUGASSERT(cf);
  if (Fetch_trc_cf_is_verbose(cf, data))
  {
    va_list ap;
    int len = 0;
    char buffer[MAXINFO + 2];
    if (data->state.feat)
      len += msnprintf(buffer + len, MAXINFO - len, "[%s] ",
                       data->state.feat->name);
    if (cf->sockindex)
      len += msnprintf(buffer + len, MAXINFO - len, "[%s-%d] ",
                       cf->cft->name, cf->sockindex);
    else
      len += msnprintf(buffer + len, MAXINFO - len, "[%s] ", cf->cft->name);
    va_start(ap, fmt);
    len += mvsnprintf(buffer + len, MAXINFO - len, fmt, ap);
    va_end(ap);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    Fetch_debug(data, FETCHINFO_TEXT, buffer, len);
  }
}

struct fetch_trc_feat Fetch_trc_feat_read = {
    "READ",
    FETCH_LOG_LVL_NONE,
};
struct fetch_trc_feat Fetch_trc_feat_write = {
    "WRITE",
    FETCH_LOG_LVL_NONE,
};

void Fetch_trc_read(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_read))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_read, fmt, ap);
    va_end(ap);
  }
}

void Fetch_trc_write(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_write))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_write, fmt, ap);
    va_end(ap);
  }
}

#ifndef FETCH_DISABLE_FTP
struct fetch_trc_feat Fetch_trc_feat_ftp = {
    "FTP",
    FETCH_LOG_LVL_NONE,
};

void Fetch_trc_ftp(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ftp))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_ftp, fmt, ap);
    va_end(ap);
  }
}
#endif /* !FETCH_DISABLE_FTP */

#ifndef FETCH_DISABLE_SMTP
struct fetch_trc_feat Fetch_trc_feat_smtp = {
    "SMTP",
    FETCH_LOG_LVL_NONE,
};

void Fetch_trc_smtp(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_smtp))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_smtp, fmt, ap);
    va_end(ap);
  }
}
#endif /* !FETCH_DISABLE_SMTP */

#ifdef USE_SSL
struct fetch_trc_feat Fetch_trc_feat_ssls = {
    "SSLS",
    FETCH_LOG_LVL_NONE,
};

void Fetch_trc_ssls(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ssls))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_ssls, fmt, ap);
    va_end(ap);
  }
}
#endif /* USE_SSL */

#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(FETCH_DISABLE_HTTP)
struct fetch_trc_feat Fetch_trc_feat_ws = {
    "WS",
    FETCH_LOG_LVL_NONE,
};

void Fetch_trc_ws(struct Fetch_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ws))
  {
    va_list ap;
    va_start(ap, fmt);
    trc_infof(data, &Fetch_trc_feat_ws, fmt, ap);
    va_end(ap);
  }
}
#endif /* !FETCH_DISABLE_WEBSOCKETS && !FETCH_DISABLE_HTTP */

#define TRC_CT_NONE (0)
#define TRC_CT_PROTOCOL (1 << (0))
#define TRC_CT_NETWORK (1 << (1))
#define TRC_CT_PROXY (1 << (2))

struct trc_feat_def
{
  struct fetch_trc_feat *feat;
  unsigned int category;
};

static struct trc_feat_def trc_feats[] = {
    {&Fetch_trc_feat_read, TRC_CT_NONE},
    {&Fetch_trc_feat_write, TRC_CT_NONE},
#ifndef FETCH_DISABLE_FTP
    {&Fetch_trc_feat_ftp, TRC_CT_PROTOCOL},
#endif
#ifndef FETCH_DISABLE_DOH
    {&Fetch_doh_trc, TRC_CT_NETWORK},
#endif
#ifndef FETCH_DISABLE_SMTP
    {&Fetch_trc_feat_smtp, TRC_CT_PROTOCOL},
#endif
#ifdef USE_SSL
    {&Fetch_trc_feat_ssls, TRC_CT_NETWORK},
#endif
#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(FETCH_DISABLE_HTTP)
    {&Fetch_trc_feat_ws, TRC_CT_PROTOCOL},
#endif
};

struct trc_cft_def
{
  struct Fetch_cftype *cft;
  unsigned int category;
};

static struct trc_cft_def trc_cfts[] = {
    {&Fetch_cft_tcp, TRC_CT_NETWORK},
    {&Fetch_cft_udp, TRC_CT_NETWORK},
    {&Fetch_cft_unix, TRC_CT_NETWORK},
    {&Fetch_cft_tcp_accept, TRC_CT_NETWORK},
    {&Fetch_cft_happy_eyeballs, TRC_CT_NETWORK},
    {&Fetch_cft_setup, TRC_CT_PROTOCOL},
#ifdef USE_NGHTTP2
    {&Fetch_cft_nghttp2, TRC_CT_PROTOCOL},
#endif
#ifdef USE_SSL
    {&Fetch_cft_ssl, TRC_CT_NETWORK},
#ifndef FETCH_DISABLE_PROXY
    {&Fetch_cft_ssl_proxy, TRC_CT_PROXY},
#endif
#endif
#if !defined(FETCH_DISABLE_PROXY)
#if !defined(FETCH_DISABLE_HTTP)
    {&Fetch_cft_h1_proxy, TRC_CT_PROXY},
#ifdef USE_NGHTTP2
    {&Fetch_cft_h2_proxy, TRC_CT_PROXY},
#endif
    {&Fetch_cft_http_proxy, TRC_CT_PROXY},
#endif /* !FETCH_DISABLE_HTTP */
    {&Fetch_cft_haproxy, TRC_CT_PROXY},
    {&Fetch_cft_socks_proxy, TRC_CT_PROXY},
#endif /* !FETCH_DISABLE_PROXY */
#ifdef USE_HTTP3
    {&Fetch_cft_http3, TRC_CT_PROTOCOL},
#endif
#if !defined(FETCH_DISABLE_HTTP)
    {&Fetch_cft_http_connect, TRC_CT_PROTOCOL},
#endif
};

static void trc_apply_level_by_name(const char *const token, int lvl)
{
  size_t i;

  for (i = 0; i < ARRAYSIZE(trc_cfts); ++i)
  {
    if (strcasecompare(token, trc_cfts[i].cft->name))
    {
      trc_cfts[i].cft->log_level = lvl;
      break;
    }
  }
  for (i = 0; i < ARRAYSIZE(trc_feats); ++i)
  {
    if (strcasecompare(token, trc_feats[i].feat->name))
    {
      trc_feats[i].feat->log_level = lvl;
      break;
    }
  }
}

static void trc_apply_level_by_category(int category, int lvl)
{
  size_t i;

  for (i = 0; i < ARRAYSIZE(trc_cfts); ++i)
  {
    if (!category || (trc_cfts[i].category & category))
      trc_cfts[i].cft->log_level = lvl;
  }
  for (i = 0; i < ARRAYSIZE(trc_feats); ++i)
  {
    if (!category || (trc_feats[i].category & category))
      trc_feats[i].feat->log_level = lvl;
  }
}

static FETCHcode trc_opt(const char *config)
{
  char *token, *tok_buf, *tmp;
  int lvl;

  tmp = strdup(config);
  if (!tmp)
    return FETCHE_OUT_OF_MEMORY;

  token = Fetch_strtok_r(tmp, ", ", &tok_buf);
  while (token)
  {
    switch (*token)
    {
    case '-':
      lvl = FETCH_LOG_LVL_NONE;
      ++token;
      break;
    case '+':
      lvl = FETCH_LOG_LVL_INFO;
      ++token;
      break;
    default:
      lvl = FETCH_LOG_LVL_INFO;
      break;
    }
    if (strcasecompare(token, "all"))
      trc_apply_level_by_category(TRC_CT_NONE, lvl);
    else if (strcasecompare(token, "protocol"))
      trc_apply_level_by_category(TRC_CT_PROTOCOL, lvl);
    else if (strcasecompare(token, "network"))
      trc_apply_level_by_category(TRC_CT_NETWORK, lvl);
    else if (strcasecompare(token, "proxy"))
      trc_apply_level_by_category(TRC_CT_PROXY, lvl);
    else
      trc_apply_level_by_name(token, lvl);

    token = Fetch_strtok_r(NULL, ", ", &tok_buf);
  }
  free(tmp);
  return FETCHE_OK;
}

FETCHcode Fetch_trc_opt(const char *config)
{
  FETCHcode result = config ? trc_opt(config) : FETCHE_OK;
#ifdef DEBUGBUILD
  /* FETCH_DEBUG can override anything */
  if (!result)
  {
    const char *dbg_config = getenv("FETCH_DEBUG");
    if (dbg_config)
      result = trc_opt(dbg_config);
  }
#endif /* DEBUGBUILD */
  return result;
}

FETCHcode Fetch_trc_init(void)
{
#ifdef DEBUGBUILD
  return Fetch_trc_opt(NULL);
#else
  return FETCHE_OK;
#endif
}

#else /* defined(FETCH_DISABLE_VERBOSE_STRINGS) */

FETCHcode Fetch_trc_init(void)
{
  return FETCHE_OK;
}

void Fetch_infof(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}

void Fetch_trc_cf_infof(struct Fetch_easy *data,
                       struct Fetch_cfilter *cf,
                       const char *fmt, ...)
{
  (void)data;
  (void)cf;
  (void)fmt;
}

struct fetch_trc_feat;

void Fetch_trc_write(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}

void Fetch_trc_read(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}

#ifndef FETCH_DISABLE_FTP
void Fetch_trc_ftp(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}
#endif
#ifndef FETCH_DISABLE_SMTP
void Fetch_trc_smtp(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}
#endif
#if !defined(FETCH_DISABLE_WEBSOCKETS) || !defined(FETCH_DISABLE_HTTP)
void Fetch_trc_ws(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}
#endif

void Fetch_trc_ssls(struct Fetch_easy *data, const char *fmt, ...)
{
  (void)data;
  (void)fmt;
}

#endif /* !defined(FETCH_DISABLE_VERBOSE_STRINGS) */
