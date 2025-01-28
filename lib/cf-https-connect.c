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

#if !defined(CURL_DISABLE_HTTP)

#include "urldata.h"
#include <curl/curl.h>
#include "curl_trc.h"
#include "cfilters.h"
#include "connect.h"
#include "hostip.h"
#include "multiif.h"
#include "cf-https-connect.h"
#include "http2.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

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
  enum alpnid alpn_id;
  BIT(shutdown);
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
  return b->cf && !b->result;
}

static bool cf_hc_baller_has_started(struct cf_hc_baller *b)
{
  return !!b->cf;
}

static int cf_hc_baller_reply_ms(struct cf_hc_baller *b,
                                 struct Curl_easy *data)
{
  if(b->cf && (b->reply_ms < 0))
    b->cf->cft->query(b->cf, data, CF_QUERY_CONNECT_REPLY_MS,
                      &b->reply_ms, NULL);
  return b->reply_ms;
}

static bool cf_hc_baller_data_pending(struct cf_hc_baller *b,
                                      const struct Curl_easy *data)
{
  return b->cf && !b->result && b->cf->cft->has_data_pending(b->cf, data);
}

static bool cf_hc_baller_needs_flush(struct cf_hc_baller *b,
                                     struct Curl_easy *data)
{
  return b->cf && !b->result && Curl_conn_cf_needs_flush(b->cf, data);
}

static CURLcode cf_hc_baller_cntrl(struct cf_hc_baller *b,
                                   struct Curl_easy *data,
                                   int event, int arg1, void *arg2)
{
  if(b->cf && !b->result)
    return Curl_conn_cf_cntrl(b->cf, data, FALSE, event, arg1, arg2);
  return CURLE_OK;
}

struct cf_hc_ctx {
  cf_hc_state state;
  const struct Curl_dns_entry *remotehost;
  struct curltime started;  /* when connect started */
  CURLcode result;          /* overall result */
  struct cf_hc_baller ballers[2];
  size_t baller_count;
  unsigned int soft_eyeballs_timeout_ms;
  unsigned int hard_eyeballs_timeout_ms;
};

static void cf_hc_baller_assign(struct cf_hc_baller *b,
                                enum alpnid alpn_id)
{
  b->alpn_id = alpn_id;
  switch(b->alpn_id) {
  case ALPN_h3:
    b->name = "h3";
    break;
  case ALPN_h2:
    b->name = "h2";
    break;
  case ALPN_h1:
    b->name = "h1";
    break;
  default:
    b->result = CURLE_FAILED_INIT;
    break;
  }
}

static void cf_hc_baller_init(struct cf_hc_baller *b,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              int transport)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct Curl_cfilter *save = cf->next;

  cf->next = NULL;
  b->started = Curl_now();
  switch(b->alpn_id) {
  case ALPN_h3:
    transport = TRNSPRT_QUIC;
    break;
  default:
    break;
  }

  if(!b->result)
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
  size_t i;

  if(ctx) {
    for(i = 0; i < ctx->baller_count; ++i)
      cf_hc_baller_reset(&ctx->ballers[i], data);
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
  int reply_ms;
  size_t i;

  DEBUGASSERT(winner->cf);
  for(i = 0; i < ctx->baller_count; ++i)
    if(winner != &ctx->ballers[i])
      cf_hc_baller_reset(&ctx->ballers[i], data);

  reply_ms = cf_hc_baller_reply_ms(winner, data);
  if(reply_ms >= 0)
    CURL_TRC_CF(data, cf, "connect+handshake %s: %dms, 1st data: %dms",
                winner->name, (int)Curl_timediff(Curl_now(), winner->started),
                reply_ms);
  else
    CURL_TRC_CF(data, cf, "deferred handshake %s: %dms",
                winner->name, (int)Curl_timediff(Curl_now(), winner->started));

  cf->next = winner->cf;
  winner->cf = NULL;

  switch(cf->conn->alpn) {
  case CURL_HTTP_VERSION_3:
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
    break;
  default:
    break;
  }
  ctx->state = CF_HC_SUCCESS;
  cf->connected = TRUE;
  return result;
}


static bool time_to_start_next(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               size_t idx, struct curltime now)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  timediff_t elapsed_ms;
  size_t i;

  if(idx >= ctx->baller_count)
    return FALSE;
  if(cf_hc_baller_has_started(&ctx->ballers[idx]))
    return FALSE;
  for(i = 0; i < idx; i++) {
    if(!ctx->ballers[i].result)
      break;
  }
  if(i == idx) {
    CURL_TRC_CF(data, cf, "all previous ballers have failed, time to start "
                "baller %zu [%s]", idx, ctx->ballers[idx].name);
    return TRUE;
  }
  elapsed_ms = Curl_timediff(now, ctx->started);
  if(elapsed_ms >= ctx->hard_eyeballs_timeout_ms) {
    CURL_TRC_CF(data, cf, "hard timeout of %dms reached, starting %s",
                ctx->hard_eyeballs_timeout_ms, ctx->ballers[idx].name);
    return TRUE;
  }

  if((idx > 0) && (elapsed_ms >= ctx->soft_eyeballs_timeout_ms)) {
    if(cf_hc_baller_reply_ms(&ctx->ballers[idx - 1], data) < 0) {
      CURL_TRC_CF(data, cf, "soft timeout of %dms reached, %s has not "
                  "seen any data, starting %s",
                  ctx->soft_eyeballs_timeout_ms,
                  ctx->ballers[idx - 1].name, ctx->ballers[idx].name);
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
  size_t i, failed_ballers;

  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  now = Curl_now();
  switch(ctx->state) {
  case CF_HC_INIT:
    DEBUGASSERT(!cf->next);
    for(i = 0; i < ctx->baller_count; i++)
      DEBUGASSERT(!ctx->ballers[i].cf);
    CURL_TRC_CF(data, cf, "connect, init");
    ctx->started = now;
    cf_hc_baller_init(&ctx->ballers[0], cf, data, cf->conn->transport);
    if(ctx->baller_count > 1) {
      Curl_expire(data, ctx->soft_eyeballs_timeout_ms, EXPIRE_ALPN_EYEBALLS);
      CURL_TRC_CF(data, cf, "set expire for starting next baller in %ums",
                  ctx->soft_eyeballs_timeout_ms);
    }
    ctx->state = CF_HC_CONNECT;
    FALLTHROUGH();

  case CF_HC_CONNECT:
    if(cf_hc_baller_is_active(&ctx->ballers[0])) {
      result = cf_hc_baller_connect(&ctx->ballers[0], cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->ballers[0]);
        goto out;
      }
    }

    if(time_to_start_next(cf, data, 1, now)) {
      cf_hc_baller_init(&ctx->ballers[1], cf, data, cf->conn->transport);
    }

    if((ctx->baller_count > 1) && cf_hc_baller_is_active(&ctx->ballers[1])) {
      CURL_TRC_CF(data, cf, "connect, check %s", ctx->ballers[1].name);
      result = cf_hc_baller_connect(&ctx->ballers[1], cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->ballers[1]);
        goto out;
      }
    }

    failed_ballers = 0;
    for(i = 0; i < ctx->baller_count; i++) {
      if(ctx->ballers[i].result)
        ++failed_ballers;
    }

    if(failed_ballers == ctx->baller_count) {
      /* all have failed. we give up */
      CURL_TRC_CF(data, cf, "connect, all failed");
      for(i = 0; i < ctx->baller_count; i++) {
        if(ctx->ballers[i].result) {
          result = ctx->ballers[i].result;
          break;
        }
      }
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
  CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  return result;
}

static CURLcode cf_hc_shutdown(struct Curl_cfilter *cf,
                               struct Curl_easy *data, bool *done)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* shutdown all ballers that have not done so already. If one fails,
   * continue shutting down others until all are shutdown. */
  for(i = 0; i < ctx->baller_count; i++) {
    struct cf_hc_baller *b = &ctx->ballers[i];
    bool bdone = FALSE;
    if(!cf_hc_baller_is_active(b) || b->shutdown)
      continue;
    b->result = b->cf->cft->do_shutdown(b->cf, data, &bdone);
    if(b->result || bdone)
      b->shutdown = TRUE; /* treat a failed shutdown as done */
  }

  *done = TRUE;
  for(i = 0; i < ctx->baller_count; i++) {
    if(!ctx->ballers[i].shutdown)
      *done = FALSE;
  }
  if(*done) {
    for(i = 0; i < ctx->baller_count; i++) {
      if(ctx->ballers[i].result)
        result = ctx->ballers[i].result;
    }
  }
  CURL_TRC_CF(data, cf, "shutdown -> %d, done=%d", result, *done);
  return result;
}

static void cf_hc_adjust_pollset(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct easy_pollset *ps)
{
  if(!cf->connected) {
    struct cf_hc_ctx *ctx = cf->ctx;
    size_t i;

    for(i = 0; i < ctx->baller_count; i++) {
      struct cf_hc_baller *b = &ctx->ballers[i];
      if(!cf_hc_baller_is_active(b))
        continue;
      Curl_conn_cf_adjust_pollset(b->cf, data, ps);
    }
    CURL_TRC_CF(data, cf, "adjust_pollset -> %d socks", ps->num);
  }
}

static bool cf_hc_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i;

  if(cf->connected)
    return cf->next->cft->has_data_pending(cf->next, data);

  CURL_TRC_CF((struct Curl_easy *)data, cf, "data_pending");
  for(i = 0; i < ctx->baller_count; i++)
    if(cf_hc_baller_data_pending(&ctx->ballers[i], data))
      return TRUE;
  return FALSE;
}

static struct curltime cf_get_max_baller_time(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              int query)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  struct curltime t, tmax;
  size_t i;

  memset(&tmax, 0, sizeof(tmax));
  for(i = 0; i < ctx->baller_count; i++) {
    struct Curl_cfilter *cfb = ctx->ballers[i].cf;
    memset(&t, 0, sizeof(t));
    if(cfb && !cfb->cft->query(cfb, data, query, NULL, &t)) {
      if((t.tv_sec || t.tv_usec) && Curl_timediff_us(t, tmax) > 0)
        tmax = t;
    }
  }
  return tmax;
}

static CURLcode cf_hc_query(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int query, int *pres1, void *pres2)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i;

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
    case CF_QUERY_NEED_FLUSH: {
      for(i = 0; i < ctx->baller_count; i++)
        if(cf_hc_baller_needs_flush(&ctx->ballers[i], data)) {
          *pres1 = TRUE;
          return CURLE_OK;
        }
      break;
    }
    default:
      break;
    }
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static CURLcode cf_hc_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int event, int arg1, void *arg2)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  size_t i;

  if(!cf->connected) {
    for(i = 0; i < ctx->baller_count; i++) {
      result = cf_hc_baller_cntrl(&ctx->ballers[i], data, event, arg1, arg2);
      if(result && (result != CURLE_AGAIN))
        goto out;
    }
    result = CURLE_OK;
  }
out:
  return result;
}

static void cf_hc_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "close");
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
  CURL_TRC_CF(data, cf, "destroy");
  cf_hc_reset(cf, data);
  Curl_safefree(ctx);
}

struct Curl_cftype Curl_cft_http_connect = {
  "HTTPS-CONNECT",
  0,
  CURL_LOG_LVL_NONE,
  cf_hc_destroy,
  cf_hc_connect,
  cf_hc_close,
  cf_hc_shutdown,
  Curl_cf_def_get_host,
  cf_hc_adjust_pollset,
  cf_hc_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  cf_hc_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_hc_query,
};

static CURLcode cf_hc_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             const struct Curl_dns_entry *remotehost,
                             enum alpnid *alpnids, size_t alpn_count)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_hc_ctx *ctx;
  CURLcode result = CURLE_OK;
  size_t i;

  DEBUGASSERT(alpnids);
  DEBUGASSERT(alpn_count);
  DEBUGASSERT(alpn_count <= ARRAYSIZE(ctx->ballers));
  if(!alpn_count || (alpn_count > ARRAYSIZE(ctx->ballers))) {
    failf(data, "https-connect filter create with unsupported %zu ALPN ids",
          alpn_count);
    return CURLE_FAILED_INIT;
  }

  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->remotehost = remotehost;
  for(i = 0; i < alpn_count; ++i)
    cf_hc_baller_assign(&ctx->ballers[i], alpnids[i]);
  for(; i < ARRAYSIZE(ctx->ballers); ++i)
    ctx->ballers[i].alpn_id = ALPN_none;
  ctx->baller_count = alpn_count;

  result = Curl_cf_create(&cf, &Curl_cft_http_connect, ctx);
  CURL_TRC_CF(data, cf, "created with %zu ALPNs -> %d",
              ctx->baller_count, result);
  if(result)
    goto out;
  ctx = NULL;
  cf_hc_reset(cf, data);

out:
  *pcf = result ? NULL : cf;
  free(ctx);
  return result;
}

static CURLcode cf_http_connect_add(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex,
                                    const struct Curl_dns_entry *remotehost,
                                    enum alpnid *alpn_ids, size_t alpn_count)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_hc_create(&cf, data, remotehost, alpn_ids, alpn_count);
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
  enum alpnid alpn_ids[2];
  size_t alpn_count = 0;
  CURLcode result = CURLE_OK;

  (void)sockindex;
  (void)remotehost;

  if(conn->bits.tls_enable_alpn) {
    switch(data->state.httpwant) {
    case CURL_HTTP_VERSION_NONE:
      /* No preferences by transfer setup. Choose best defaults */
#ifdef USE_HTTPSRR
      if(conn->dns_entry && conn->dns_entry->hinfo &&
         !conn->dns_entry->hinfo->no_def_alpn) {
        size_t i, j;
        for(i = 0; i < ARRAYSIZE(conn->dns_entry->hinfo->alpns) &&
                   alpn_count < ARRAYSIZE(alpn_ids); ++i) {
          bool present = FALSE;
          enum alpnid alpn = conn->dns_entry->hinfo->alpns[i];
          for(j = 0; j < alpn_count; ++j) {
            if(alpn == alpn_ids[j]) {
              present = TRUE;
              break;
            }
          }
          if(!present) {
            switch(alpn) {
            case ALPN_h3:
              if(Curl_conn_may_http3(data, conn))
                break;  /* not possible */
              FALLTHROUGH();
            case ALPN_h2:
            case ALPN_h1:
              alpn_ids[alpn_count++] = alpn;
              break;
            default: /* ignore */
              break;
            }
          }
        }
      }
#endif
      if(!alpn_count)
        alpn_ids[alpn_count++] = ALPN_h2;
      break;
    case CURL_HTTP_VERSION_3ONLY:
      result = Curl_conn_may_http3(data, conn);
      if(result) /* cannot do it */
        goto out;
      alpn_ids[alpn_count++] = ALPN_h3;
      break;
    case CURL_HTTP_VERSION_3:
      /* We assume that silently not even trying H3 is ok here */
      /* TODO: should we fail instead? */
      if(Curl_conn_may_http3(data, conn) == CURLE_OK)
        alpn_ids[alpn_count++] = ALPN_h3;
      alpn_ids[alpn_count++] = ALPN_h2;
      break;
    case CURL_HTTP_VERSION_2_0:
    case CURL_HTTP_VERSION_2TLS:
    case CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE:
      alpn_ids[alpn_count++] = ALPN_h2;
      break;
    case CURL_HTTP_VERSION_1_0:
    case CURL_HTTP_VERSION_1_1:
      alpn_ids[alpn_count++] = ALPN_h1;
      break;
    default:
      alpn_ids[alpn_count++] = ALPN_h2;
      break;
    }
  }

  /* If we identified ALPNs to use, install our filter. Otherwise,
   * install nothing, so our call will use a default connect setup. */
  if(alpn_count) {
    result = cf_http_connect_add(data, conn, sockindex, remotehost,
                                 alpn_ids, alpn_count);
  }

out:
  return result;
}

#endif /* !defined(CURL_DISABLE_HTTP) */
