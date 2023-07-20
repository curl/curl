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

#if !defined(CURL_DISABLE_HTTP) && !defined(USE_HYPER)

#include "urldata.h"
#include <curl/curl.h>
#include "curl_log.h"
#include "cfilters.h"
#include "connect.h"
#include "multiif.h"
#include "cf-https-connect.h"
#include "http2.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


typedef enum {
  CF_HC_INIT,
  CF_HC_CONNECT,
  CF_HC_SUCCESS,
  CF_HC_FAILURE
} cf_hc_state;

struct cf_hc_baller {
  const char *name;
  struct Curl_cfilter *cf;
  CURLcode result;
  struct curltime started;
  int reply_ms;
  bool enabled;
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
  b->reply_ms = -1;
}

static bool cf_hc_baller_is_active(struct cf_hc_baller *b)
{
  return b->enabled && b->cf && !b->result;
}

static bool cf_hc_baller_has_started(struct cf_hc_baller *b)
{
  return !!b->cf;
}

static int cf_hc_baller_reply_ms(struct cf_hc_baller *b,
                                 struct Curl_easy *data)
{
  if(b->reply_ms < 0)
    b->cf->cft->query(b->cf, data, CF_QUERY_CONNECT_REPLY_MS,
                      &b->reply_ms, NULL);
  return b->reply_ms;
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
  int soft_eyeballs_timeout_ms;
  int hard_eyeballs_timeout_ms;
};

static void cf_hc_baller_init(struct cf_hc_baller *b,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *name,
                              int transport)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct Curl_cfilter *save = cf->next;

  b->name = name;
  cf->next = NULL;
  b->started = Curl_now();
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
    ctx->hard_eyeballs_timeout_ms = data->set.happy_eyeballs_timeout;
    ctx->soft_eyeballs_timeout_ms = data->set.happy_eyeballs_timeout / 2;
  }
}

static CURLcode baller_connected(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_hc_baller *winner)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(winner->cf);
  if(winner != &ctx->h3_baller)
    cf_hc_baller_reset(&ctx->h3_baller, data);
  if(winner != &ctx->h21_baller)
    cf_hc_baller_reset(&ctx->h21_baller, data);

  DEBUGF(LOG_CF(data, cf, "connect+handshake %s: %dms, 1st data: %dms",
                winner->name, (int)Curl_timediff(Curl_now(), winner->started),
                cf_hc_baller_reply_ms(winner, data)));
  cf->next = winner->cf;
  winner->cf = NULL;

  switch(cf->conn->alpn) {
  case CURL_HTTP_VERSION_3:
    infof(data, "using HTTP/3");
    break;
  case CURL_HTTP_VERSION_2:
#ifdef USE_NGHTTP2
    /* Using nghttp2, we add the filter "below" us, so when the conn
     * closes, we tear it down for a fresh reconnect */
    result = Curl_http2_switch_at(cf, data);
    if(result) {
      ctx->state = CF_HC_FAILURE;
      ctx->result = result;
      return result;
    }
#endif
    infof(data, "using HTTP/2");
    break;
  case CURL_HTTP_VERSION_1_1:
    infof(data, "using HTTP/1.1");
    break;
  default:
    infof(data, "using HTTP/1.x");
    break;
  }
  ctx->state = CF_HC_SUCCESS;
  cf->connected = TRUE;
  Curl_conn_cf_cntrl(cf->next, data, TRUE,
                     CF_CTRL_CONN_INFO_UPDATE, 0, NULL);
  return result;
}


static bool time_to_start_h21(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct curltime now)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  timediff_t elapsed_ms;

  if(!ctx->h21_baller.enabled || cf_hc_baller_has_started(&ctx->h21_baller))
    return FALSE;

  if(!ctx->h3_baller.enabled || !cf_hc_baller_is_active(&ctx->h3_baller))
    return TRUE;

  elapsed_ms = Curl_timediff(now, ctx->started);
  if(elapsed_ms >= ctx->hard_eyeballs_timeout_ms) {
    DEBUGF(LOG_CF(data, cf, "hard timeout of %dms reached, starting h21",
                  ctx->hard_eyeballs_timeout_ms));
    return TRUE;
  }

  if(elapsed_ms >= ctx->soft_eyeballs_timeout_ms) {
    if(cf_hc_baller_reply_ms(&ctx->h3_baller, data) < 0) {
      DEBUGF(LOG_CF(data, cf, "soft timeout of %dms reached, h3 has not "
                    "seen any data, starting h21",
                    ctx->soft_eyeballs_timeout_ms));
      return TRUE;
    }
    /* set the effective hard timeout again */
    Curl_expire(data, ctx->hard_eyeballs_timeout_ms - elapsed_ms,
                EXPIRE_ALPN_EYEBALLS);
  }
  return FALSE;
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
    if(ctx->h3_baller.enabled) {
      cf_hc_baller_init(&ctx->h3_baller, cf, data, "h3", TRNSPRT_QUIC);
      if(ctx->h21_baller.enabled)
        Curl_expire(data, ctx->soft_eyeballs_timeout_ms, EXPIRE_ALPN_EYEBALLS);
    }
    else if(ctx->h21_baller.enabled)
      cf_hc_baller_init(&ctx->h21_baller, cf, data, "h21",
                       cf->conn->transport);
    ctx->state = CF_HC_CONNECT;
    /* FALLTHROUGH */

  case CF_HC_CONNECT:
    if(cf_hc_baller_is_active(&ctx->h3_baller)) {
      result = cf_hc_baller_connect(&ctx->h3_baller, cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->h3_baller);
        goto out;
      }
    }

    if(time_to_start_h21(cf, data, now)) {
      cf_hc_baller_init(&ctx->h21_baller, cf, data, "h21",
                        cf->conn->transport);
    }

    if(cf_hc_baller_is_active(&ctx->h21_baller)) {
      DEBUGF(LOG_CF(data, cf, "connect, check h21"));
      result = cf_hc_baller_connect(&ctx->h21_baller, cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->h21_baller);
        goto out;
      }
    }

    if((!ctx->h3_baller.enabled || ctx->h3_baller.result) &&
       (!ctx->h21_baller.enabled || ctx->h21_baller.result)) {
      /* both failed or disabled. we give up */
      DEBUGF(LOG_CF(data, cf, "connect, all failed"));
      result = ctx->result = ctx->h3_baller.enabled?
                              ctx->h3_baller.result : ctx->h21_baller.result;
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
  DEBUGF(LOG_CF(data, cf, "connect -> %d, done=%d", result, *done));
  return result;
}

static int cf_hc_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *socks)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i, j, s;
  int brc, rc = GETSOCK_BLANK;
  curl_socket_t bsocks[MAX_SOCKSPEREASYHANDLE];
  struct cf_hc_baller *ballers[2];

  if(cf->connected)
    return cf->next->cft->get_select_socks(cf->next, data, socks);

  ballers[0] = &ctx->h3_baller;
  ballers[1] = &ctx->h21_baller;
  for(i = s = 0; i < sizeof(ballers)/sizeof(ballers[0]); i++) {
    struct cf_hc_baller *b = ballers[i];
    if(!cf_hc_baller_is_active(b))
      continue;
    brc = Curl_conn_cf_get_select_socks(b->cf, data, bsocks);
    DEBUGF(LOG_CF(data, cf, "get_selected_socks(%s) -> %x", b->name, brc));
    if(!brc)
      continue;
    for(j = 0; j < MAX_SOCKSPEREASYHANDLE && s < MAX_SOCKSPEREASYHANDLE; ++j) {
      if((brc & GETSOCK_WRITESOCK(j)) || (brc & GETSOCK_READSOCK(j))) {
        socks[s] = bsocks[j];
        if(brc & GETSOCK_WRITESOCK(j))
          rc |= GETSOCK_WRITESOCK(s);
        if(brc & GETSOCK_READSOCK(j))
          rc |= GETSOCK_READSOCK(s);
        s++;
      }
    }
  }
  DEBUGF(LOG_CF(data, cf, "get_selected_socks -> %x", rc));
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

static struct curltime cf_get_max_baller_time(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              int query)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct Curl_cfilter *cfb;
  struct curltime t, tmax;

  memset(&tmax, 0, sizeof(tmax));
  memset(&t, 0, sizeof(t));
  cfb = ctx->h21_baller.enabled? ctx->h21_baller.cf : NULL;
  if(cfb && !cfb->cft->query(cfb, data, query, NULL, &t)) {
    if((t.tv_sec || t.tv_usec) && Curl_timediff_us(t, tmax) > 0)
      tmax = t;
  }
  memset(&t, 0, sizeof(t));
  cfb = ctx->h3_baller.enabled? ctx->h3_baller.cf : NULL;
  if(cfb && !cfb->cft->query(cfb, data, query, NULL, &t)) {
    if((t.tv_sec || t.tv_usec) && Curl_timediff_us(t, tmax) > 0)
      tmax = t;
  }
  return tmax;
}

static CURLcode cf_hc_query(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int query, int *pres1, void *pres2)
{
  if(!cf->connected) {
    switch(query) {
    case CF_QUERY_TIMER_CONNECT: {
      struct curltime *when = pres2;
      *when = cf_get_max_baller_time(cf, data, CF_QUERY_TIMER_CONNECT);
      return CURLE_OK;
    }
    case CF_QUERY_TIMER_APPCONNECT: {
      struct curltime *when = pres2;
      *when = cf_get_max_baller_time(cf, data, CF_QUERY_TIMER_APPCONNECT);
      return CURLE_OK;
    }
    default:
      break;
    }
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static void cf_hc_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  DEBUGF(LOG_CF(data, cf, "close"));
  cf_hc_reset(cf, data);
  cf->connected = FALSE;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
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
  "HTTPS-CONNECT",
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
  cf_hc_query,
};

static CURLcode cf_hc_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             const struct Curl_dns_entry *remotehost,
                             bool try_h3, bool try_h21)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_hc_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->remotehost = remotehost;
  ctx->h3_baller.enabled = try_h3;
  ctx->h21_baller.enabled = try_h21;

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

static CURLcode cf_http_connect_add(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex,
                                    const struct Curl_dns_entry *remotehost,
                                    bool try_h3, bool try_h21)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_hc_create(&cf, data, remotehost, try_h3, try_h21);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
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
    /* TODO: should we fail instead? */
    try_h3 = (Curl_conn_may_http3(data, conn) == CURLE_OK);
    try_h21 = TRUE;
  }

  result = cf_http_connect_add(data, conn, sockindex, remotehost,
                               try_h3, try_h21);
out:
  return result;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(USE_HYPER) */
