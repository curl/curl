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

#ifndef CURL_DISABLE_HTTP

#include "urldata.h"
#include <curl/curl.h>
#include "curl_log.h"
#include "cfilters.h"
#include "connect.h"
#include "multiif.h"
#include "cf-http.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

typedef enum {
  CF_HC_INIT,
  CF_HC_CONNECT,
  CF_HC_SUCCESS,
  CF_HC_FAILURE,
} cf_hc_state;

struct cf_hc_baller {
  struct Curl_cfilter *cf;
  CURLcode result;
  timediff_t delay_ms;
};

static void cf_hc_baller_reset(struct cf_hc_baller *b,
                               struct Curl_easy *data)
{
  if(b->cf) {
    Curl_conn_cf_close(b->cf, data);
    Curl_conn_cf_discard_chain(&b->cf, data);
    b->cf = NULL;
  }
  b->result = CURLE_OK;
}

static bool cf_hc_baller_is_active(struct cf_hc_baller *b)
{
  return b->cf && !b->result;
}

static bool cf_hc_baller_has_started(struct cf_hc_baller *b)
{
  return !!b->cf;
}

static bool cf_hc_baller_data_pending(struct cf_hc_baller *b,
                                      const struct Curl_easy *data)
{
  return b->cf && !b->result && b->cf->cft->has_data_pending(b->cf, data);
}

struct cf_hc_ctx {
  cf_hc_state state;
  const struct Curl_dns_entry *remotehost;
  struct curltime started;  /* when connect started */
  CURLcode result;          /* overall result */
  struct cf_hc_baller h3_baller;
  struct cf_hc_baller h21_baller;
};

static void cf_hc_baller_init(struct cf_hc_baller *b,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              int transport)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct Curl_cfilter *save = cf->next;

  cf->next = NULL;
  b->result = Curl_cf_setup_insert_after(cf, data, ctx->remotehost,
                                         transport, CURL_CF_SSL_ENABLE);
  b->cf = cf->next;
  cf->next = save;
}

static CURLcode cf_hc_baller_connect(struct cf_hc_baller *b,
                                     struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     bool *done)
{
  struct Curl_cfilter *save = cf->next;

  cf->next = b->cf;
  b->result = Curl_conn_cf_connect(cf->next, data, FALSE, done);
  b->cf = cf->next; /* it might mutate */
  cf->next = save;
  return b->result;
}

static void cf_hc_reset(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;

  if(ctx) {
    cf_hc_baller_reset(&ctx->h3_baller, data);
    cf_hc_baller_reset(&ctx->h21_baller, data);
    ctx->state = CF_HC_INIT;
    ctx->result = CURLE_OK;
    ctx->h21_baller.delay_ms = 100; /* arbitrary */
  }
}

static CURLcode cf_hc_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct curltime now;
  CURLcode result = CURLE_OK;

  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  now = Curl_now();
  switch(ctx->state) {
  case CF_HC_INIT:
    DEBUGASSERT(!ctx->h3_baller.cf);
    DEBUGASSERT(!ctx->h21_baller.cf);
    DEBUGASSERT(!cf->next);
    DEBUGF(LOG_CF(data, cf, "connect, init"));
    ctx->started = now;
    cf_hc_baller_init(&ctx->h3_baller, cf, data, TRNSPRT_QUIC);
    ctx->state = CF_HC_CONNECT;
    /* FALLTHROUGH */

  case CF_HC_CONNECT:
    if(cf_hc_baller_is_active(&ctx->h3_baller)) {
      DEBUGF(LOG_CF(data, cf, "connect, check h3"));
      result = cf_hc_baller_connect(&ctx->h3_baller, cf, data, done);
      if(!result && *done) {
        DEBUGF(LOG_CF(data, cf, "connect, h3 connected"));
        cf_hc_baller_reset(&ctx->h21_baller, data);
        ctx->state = CF_HC_SUCCESS;
        cf->next = ctx->h3_baller.cf;
        ctx->h3_baller.cf = NULL;
        cf->connected = TRUE;
        goto out;
      }
    }

    if(!cf_hc_baller_has_started(&ctx->h21_baller) &&
       (ctx->h3_baller.result
        || Curl_timediff(now, ctx->started) >= ctx->h21_baller.delay_ms)) {
       /* h3 failed or delay expired, start h21 attempt */
       DEBUGF(LOG_CF(data, cf, "connect, start h21"));
       cf_hc_baller_init(&ctx->h21_baller, cf, data, TRNSPRT_TCP);
    }

    if(cf_hc_baller_is_active(&ctx->h21_baller)) {
      DEBUGF(LOG_CF(data, cf, "connect, check h21"));
      result = cf_hc_baller_connect(&ctx->h21_baller, cf, data, done);
      if(!result && *done) {
        DEBUGF(LOG_CF(data, cf, "connect, h21 connected"));
        cf_hc_baller_reset(&ctx->h3_baller, data);
        ctx->state = CF_HC_SUCCESS;
        cf->next = ctx->h21_baller.cf;
        ctx->h21_baller.cf = NULL;
        cf->connected = TRUE;
        goto out;
      }
    }

    if(ctx->h3_baller.result && ctx->h21_baller.result) {
      /* both failed. we give up */
      DEBUGF(LOG_CF(data, cf, "connect, all failed"));
      result = ctx->result = ctx->h3_baller.result;
      ctx->state = CF_HC_FAILURE;
      goto out;
    }
    result = CURLE_OK;
    *done = FALSE;
    break;

  case CF_HC_FAILURE:
    result = ctx->result;
    cf->connected = FALSE;
    *done = FALSE;
    break;

  case CF_HC_SUCCESS:
    result = CURLE_OK;
    cf->connected = TRUE;
    *done = TRUE;
    break;
  }

out:
  return result;
}

static int cf_hc_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *socks)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i, j, s;
  int wrc, rc = GETSOCK_BLANK;
  curl_socket_t wsocks[MAX_SOCKSPEREASYHANDLE];
  struct cf_hc_baller *ballers[2];

  if(cf->connected)
    return cf->next->cft->get_select_socks(cf->next, data, socks);

  DEBUGF(LOG_CF(data, cf, "get_select_socks"));
  ballers[0] = &ctx->h3_baller;
  ballers[1] = &ctx->h21_baller;
  for(i = s = 0; i < sizeof(ballers)/sizeof(ballers[0]); i++) {
    struct cf_hc_baller *baller = ballers[i];
    if(!cf_hc_baller_is_active(baller))
      continue;
    wrc = Curl_conn_cf_get_select_socks(baller->cf, data, wsocks);
    if(!wrc)
      continue;
    for(j = 0; j < MAX_SOCKSPEREASYHANDLE && s < MAX_SOCKSPEREASYHANDLE; ++j) {
      if((wrc & GETSOCK_WRITESOCK(j)) || (wrc & GETSOCK_READSOCK(j))) {
        socks[s] = wsocks[j];
        if(wrc & GETSOCK_WRITESOCK(j))
          rc |= GETSOCK_WRITESOCK(s);
        if(wrc & GETSOCK_READSOCK(j))
          rc |= GETSOCK_READSOCK(s);
        s++;
      }
    }
  }
  return rc;
}

static bool cf_hc_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;

  if(cf->connected)
    return cf->next->cft->has_data_pending(cf->next, data);

  DEBUGF(LOG_CF((struct Curl_easy *)data, cf, "data_pending"));
  return cf_hc_baller_data_pending(&ctx->h3_baller, data)
         || cf_hc_baller_data_pending(&ctx->h21_baller, data);
}

static void cf_hc_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  DEBUGF(LOG_CF(data, cf, "close"));
  cf_hc_reset(cf, data);
  cf->connected = FALSE;

  if(cf->next) {
    cf->next->cft->close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static void cf_hc_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;

  (void)data;
  DEBUGF(LOG_CF(data, cf, "destroy"));
  cf_hc_reset(cf, data);
  Curl_safefree(ctx);
}

struct Curl_cftype Curl_cft_http_connect = {
  "HTTP-CONNECT",
  0,
  CURL_LOG_DEFAULT,
  cf_hc_destroy,
  cf_hc_connect,
  cf_hc_close,
  Curl_cf_def_get_host,
  cf_hc_get_select_socks,
  cf_hc_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_hc_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             const struct Curl_dns_entry *remotehost)
{
  struct Curl_cfilter *cf;
  struct cf_hc_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->remotehost = remotehost;

  result = Curl_cf_create(&cf, &Curl_cft_http_connect, ctx);
  if(result)
    goto out;
  ctx = NULL;
  cf_hc_reset(cf, data);

out:
  *pcf = result? NULL : cf;
  free(ctx);
  return result;
}

CURLcode Curl_cf_http_connect_add(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex,
                                  const struct Curl_dns_entry *remotehost)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_hc_create(&cf, data, remotehost);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

CURLcode
Curl_cf_http_connect_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data,
                                  const struct Curl_dns_entry *remotehost)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);
  result = cf_hc_create(&cf, data, remotehost);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);
out:
  return result;
}

CURLcode Curl_cf_https_setup(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             const struct Curl_dns_entry *remotehost)
{
  bool try_h3 = FALSE, try_h21 = TRUE; /* defaults, for now */
  CURLcode result = CURLE_OK;

  (void)sockindex;
  (void)remotehost;

  if(!conn->bits.tls_enable_alpn)
    goto out;

  if(data->state.httpwant == CURL_HTTP_VERSION_3ONLY) {
    result = Curl_conn_may_http3(data, conn);
    if(result) /* can't do it */
      goto out;
    try_h3 = TRUE;
    try_h21 = FALSE;
  }
  else if(data->state.httpwant >= CURL_HTTP_VERSION_3) {
    /* We assume that silently not even trying H3 is ok here */
    try_h3 = (Curl_conn_may_http3(data, conn) == CURLE_OK);
    try_h21 = TRUE;
  }

  if(!try_h3) {
    /* The default setup filter knows how to handle TRNSPRT_TCP
     * for HTTP/2 and/or HTTP/1.x */
    conn->transport = TRNSPRT_TCP;
    goto out;
  }
  else if(!try_h21) {
    /* The default setup filter knows how to handle TRNSPRT_QUIC
     * for pure HTTP/3 */
    conn->transport = TRNSPRT_QUIC;
    goto out;
  }

  /* ALPN eyeball scenario. Install the HTTP-SETUP filter */
  result = Curl_cf_http_connect_add(data, conn, sockindex, remotehost);

out:
  return result;
}

#endif /* !CURL_DISABLE_HTTP */
