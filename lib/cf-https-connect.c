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
#include "curl_trc.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "connect.h"
#include "hostip.h"
#include "httpsrr.h"
#include "multiif.h"
#include "cf-https-connect.h"
#include "http2.h"
#include "progress.h"
#include "select.h"
#include "vquic/vquic.h"

typedef enum {
  CF_HC_RESOLV,
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
  uint8_t transport;
  enum alpnid alpn_id;
  BIT(shutdown);
};

static void cf_hc_baller_discard(struct cf_hc_baller *b,
                                 struct Curl_easy *data)
{
  if(b->cf) {
    Curl_conn_cf_close(b->cf, data);
    Curl_conn_cf_discard_chain(&b->cf, data);
    b->cf = NULL;
  }
}

static bool cf_hc_baller_is_connecting(struct cf_hc_baller *b)
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
  struct curltime started;  /* when connect started */
  CURLcode result;          /* overall result */
  CURLcode check_h3_result;
  struct cf_hc_baller ballers[2];
  size_t baller_count;
  timediff_t soft_eyeballs_timeout_ms;
  timediff_t hard_eyeballs_timeout_ms;
  uint8_t def_transport;
  BIT(httpsrr_resolved);
  BIT(checked_h3);
  BIT(ballers_complete);
};

static void cf_hc_ctx_close(struct Curl_easy *data,
                            struct cf_hc_ctx *ctx)
{
  if(ctx) {
    size_t i;
    for(i = 0; i < ctx->baller_count; ++i)
      cf_hc_baller_discard(&ctx->ballers[i], data);
  }
}

static void cf_hc_ctx_destroy(struct Curl_easy *data,
                              struct cf_hc_ctx *ctx)
{
  if(ctx) {
    cf_hc_ctx_close(data, ctx);
    curlx_free(ctx);
  }
}

static void cf_hc_baller_assign(struct cf_hc_baller *b,
                                enum alpnid alpn_id,
                                uint8_t def_transport)
{
  b->alpn_id = alpn_id;
  b->transport = def_transport;
  b->cf = NULL;
  b->result = CURLE_OK;
  b->reply_ms = -1;
  b->shutdown = FALSE;
  switch(b->alpn_id) {
  case ALPN_h3:
    b->name = "h3";
    b->transport = TRNSPRT_QUIC;
    break;
  case ALPN_h2:
    b->name = "h2";
    break;
  case ALPN_h1:
    b->name = "h1";
    break;
  case ALPN_none:
    b->name = "no-alpn";
    break;
  default:
    b->result = CURLE_FAILED_INIT;
    break;
  }
}

static void cf_hc_baller_init(struct cf_hc_baller *b,
                              struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct Curl_cfilter *save = cf->next;

  cf->next = NULL;
  b->started = *Curl_pgrs_now(data);
  b->result = Curl_cf_setup_insert_after(cf, data, b->transport,
                                         CURL_CF_SSL_ENABLE);
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
  b->result = Curl_conn_cf_connect(cf->next, data, done);
  b->cf = cf->next; /* it might mutate */
  cf->next = save;
  return b->result;
}

static CURLcode baller_connected(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_hc_baller *winner)
{
  struct cf_hc_ctx *ctx = cf->ctx;

  /* Make the winner's connection filter out own sub-filter, check, move,
   * close all remaining. */
  if(cf->next) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }
  if(!winner->cf) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }

  cf->next = winner->cf;
  winner->cf = NULL;
  ctx->state = CF_HC_SUCCESS;
  cf->connected = TRUE;

  cf_hc_ctx_close(data, ctx);
  /* ballers may have failf()'d, the winner resets it, so our
   * errorbuf is clean again. */
  Curl_reset_fail(data);

#ifdef USE_NGHTTP2
  {
    /* For a negotiated HTTP/2 connection insert the h2 filter. */
    const char *alpn = Curl_conn_cf_get_alpn_negotiated(cf->next, data);
    if(alpn && !strcmp("h2", alpn)) {
      CURLcode result = Curl_http2_switch_at(cf, data);
      if(result) {
        ctx->state = CF_HC_FAILURE;
        ctx->result = result;
        return result;
      }
    }
  }
#endif
  return CURLE_OK;
}

static bool time_to_start_baller2(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  timediff_t elapsed_ms;

  if(ctx->baller_count < 2)
    return FALSE;
  else if(cf_hc_baller_has_started(&ctx->ballers[1]))
    return FALSE;
  else if(ctx->ballers[0].result) {
    CURL_TRC_CF(data, cf, "%s baller failed, starting %s",
                ctx->ballers[0].name, ctx->ballers[1].name);
    return TRUE;
  }

  elapsed_ms = curlx_ptimediff_ms(Curl_pgrs_now(data), &ctx->started);
  if(elapsed_ms >= ctx->hard_eyeballs_timeout_ms) {
    CURL_TRC_CF(data, cf, "%s inconclusive after %" FMT_TIMEDIFF_T ", "
                "starting %s", ctx->ballers[0].name,
                ctx->hard_eyeballs_timeout_ms, ctx->ballers[1].name);
    return TRUE;
  }
  else if(elapsed_ms >= ctx->soft_eyeballs_timeout_ms) {
    if(cf_hc_baller_reply_ms(&ctx->ballers[0], data) < 0) {
      CURL_TRC_CF(data, cf, "%s has not seen any data after %"
                  FMT_TIMEDIFF_T "ms, starting %s",
                  ctx->ballers[0].name, ctx->soft_eyeballs_timeout_ms,
                  ctx->ballers[1].name);
      return TRUE;
    }
  }
  return FALSE;
}

static bool cf_hc_may_h3(struct Curl_cfilter *cf,
                         struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  if(!ctx->checked_h3) {
    ctx->check_h3_result =
      Curl_conn_may_http3(data, cf->conn, ctx->def_transport);
    ctx->checked_h3 = TRUE;
  }
  return !ctx->check_h3_result;
}

static enum alpnid cf_hc_get_httpsrr_alpn(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          enum alpnid not_this_one)
{
#ifdef USE_HTTPSRR
  /* Is there an HTTPSRR use its ALPNs here.
   * We are here after having selected a connection to a host+port and
   * can no longer change that. Any HTTPSRR advice for other hosts and ports
   * we need to ignore. */
  const struct Curl_https_rrinfo *rr;
  size_t i;

  /* Do we have HTTPS-RR information? */
  rr = Curl_conn_dns_get_https(data, cf->sockindex);

  /* We do not support `rr->no_def_alpn`. */
  if(Curl_httpsrr_applicable(data, rr) && !rr->no_def_alpn) {
    for(i = 0; i < CURL_ARRAYSIZE(rr->alpns); ++i) {
      enum alpnid alpn_rr = (enum alpnid)rr->alpns[i];
      if(alpn_rr == not_this_one) /* don't want this one */
        continue;
      switch(alpn_rr) {
      case ALPN_h3:
        if((data->state.http_neg.allowed & CURL_HTTP_V3x) &&
           cf_hc_may_h3(cf, data)) {
          return alpn_rr;
        }
        break;
      case ALPN_h2:
        if(data->state.http_neg.allowed & CURL_HTTP_V2x) {
          return alpn_rr;
        }
        break;
      case ALPN_h1:
        if(data->state.http_neg.allowed & CURL_HTTP_V1x) {
          return alpn_rr;
        }
        break;
      default: /* ignore */
        break;
      }
    }
  }
#else
  (void)cf;
  (void)data;
  (void)not_this_one;
#endif
  return ALPN_none;
}

static enum alpnid cf_hc_get_pref_alpn(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       enum alpnid not_this_one)
{
  if((data->state.http_neg.preferred & data->state.http_neg.allowed)) {
    switch(data->state.http_neg.preferred) {
    case CURL_HTTP_V3x:
      if(cf_hc_may_h3(cf, data) && (ALPN_h3 != not_this_one))
        return ALPN_h3;
      break;
    case CURL_HTTP_V2x:
      if(ALPN_h2 != not_this_one)
        return ALPN_h2;
      break;
    case CURL_HTTP_V1x:
      /* If we are trying h2 already, h1 is already used as fallback */
      if((ALPN_h1 != not_this_one) && (ALPN_h2 != not_this_one))
        return ALPN_h1;
      break;
    default:
      break;
    }
  }
  return ALPN_none;
}

static enum alpnid cf_hc_get_first_alpn(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        http_majors choices,
                                        enum alpnid not_this_one)
{
  /* When told to not try h2, we also do not try h1 and vice versa */
  bool allow_h1_or_h2 = (not_this_one != ALPN_h1) &&
                        (not_this_one != ALPN_h2);
  if((ALPN_h3 != not_this_one) && (choices & CURL_HTTP_V3x) &&
     cf_hc_may_h3(cf, data)) {
    return ALPN_h3;
  }
  if(allow_h1_or_h2 && (choices & CURL_HTTP_V2x)) {
    return ALPN_h2;
  }
  if(allow_h1_or_h2 && (choices & CURL_HTTP_V1x)) {
    return ALPN_h1;
  }
  return ALPN_none;
}

static CURLcode cf_hc_set_baller1(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  enum alpnid alpn1 = ALPN_none;
  VERBOSE(const char *source = "HTTPS-RR");

  DEBUGASSERT(cf->conn->bits.tls_enable_alpn);

  alpn1 = cf_hc_get_httpsrr_alpn(cf, data, ALPN_none);
  if(alpn1 == ALPN_none) {
    /* preference is configured and allowed, can we use it? */
    VERBOSE(source = "preferred version");
    alpn1 = cf_hc_get_pref_alpn(cf, data, ALPN_none);
  }
  if(alpn1 == ALPN_none) {
    VERBOSE(source = "wanted versions");
    alpn1 = cf_hc_get_first_alpn(cf, data,
                                 data->state.http_neg.wanted,
                                 ALPN_none);
  }
  if(alpn1 == ALPN_none) {
    VERBOSE(source = "allowed versions");
    alpn1 = cf_hc_get_first_alpn(cf, data,
                                 data->state.http_neg.allowed,
                                 ALPN_none);
  }

  if(alpn1 == ALPN_none) {
    /* None of the wanted/allowed HTTP versions could be chosen */
    if(ctx->check_h3_result) {
      CURL_TRC_CF(data, cf, "unable to use HTTP/3");
      return ctx->check_h3_result;
    }
    CURL_TRC_CF(data, cf, "unable to select HTTP version");
    return CURLE_FAILED_INIT;
  }

  cf_hc_baller_assign(&ctx->ballers[0], alpn1, ctx->def_transport);
  ctx->baller_count = 1;
  CURL_TRC_CF(data, cf, "1st attempt uses %s from %s",
              ctx->ballers[0].name, source);

  switch(alpn1) {
  case ALPN_h1:
    /* We really want h1, switch off h2 to make it disappear in ALPN */
    data->state.http_neg.wanted &= (uint8_t)~CURL_HTTP_V2x;
    break;
  default:
    break;
  }

  return CURLE_OK;
}

static void cf_hc_set_baller2(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  enum alpnid alpn2 = ALPN_none, alpn1 = ctx->ballers[0].alpn_id;
  VERBOSE(const char *source = "HTTPS-RR");

  if(ctx->ballers_complete)
    return; /* already done */
  if(!ctx->httpsrr_resolved)
    return; /* HTTPS-RR pending */

  alpn2 = cf_hc_get_httpsrr_alpn(cf, data, alpn1);
  if(alpn2 == ALPN_none) {
    /* preference is configured and allowed, can we use it? */
    VERBOSE(source = "preferred version");
    alpn2 = cf_hc_get_pref_alpn(cf, data, alpn1);
  }
  if(alpn2 == ALPN_none) {
    VERBOSE(source = "wanted versions");
    alpn2 = cf_hc_get_first_alpn(cf, data,
                                 data->state.http_neg.wanted,
                                 alpn1);
  }

  if(alpn2 != ALPN_none) {
    cf_hc_baller_assign(&ctx->ballers[1], alpn2, ctx->def_transport);
    ctx->baller_count = 2;
    CURL_TRC_CF(data, cf, "2nd attempt uses %s from %s",
                ctx->ballers[1].name, source);
  }
  ctx->ballers_complete = TRUE;
}

static CURLcode cf_hc_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  if(!ctx->httpsrr_resolved) {
    ctx->httpsrr_resolved = Curl_conn_dns_resolved_https(data, cf->sockindex);
#ifdef DEBUGBUILD
    if(!ctx->httpsrr_resolved && getenv("CURL_DBG_AWAIT_HTTPSRR")) {
      CURL_TRC_CF(data, cf, "awaiting HTTPS-RR");
      return CURLE_OK;
    }
#endif
  }

  switch(ctx->state) {
  case CF_HC_RESOLV:
    ctx->state = CF_HC_INIT;
    FALLTHROUGH();

  case CF_HC_INIT:
    DEBUGASSERT(!cf->next);
    CURL_TRC_CF(data, cf, "connect, init");
    result = cf_hc_set_baller1(cf, data);
    if(result) {
      ctx->result = result;
      ctx->state = CF_HC_FAILURE;
      goto out;
    }
    cf_hc_set_baller2(cf, data);
    ctx->started = *Curl_pgrs_now(data);
    cf_hc_baller_init(&ctx->ballers[0], cf, data);
    if((ctx->baller_count > 1) || !ctx->ballers_complete) {
      Curl_expire(data, ctx->soft_eyeballs_timeout_ms, EXPIRE_ALPN_EYEBALLS);
    }
    ctx->state = CF_HC_CONNECT;
    FALLTHROUGH();

  case CF_HC_CONNECT:
    if(!ctx->ballers_complete)
      cf_hc_set_baller2(cf, data);

    if(cf_hc_baller_is_connecting(&ctx->ballers[0])) {
      result = cf_hc_baller_connect(&ctx->ballers[0], cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->ballers[0]);
        goto out;
      }
    }

    if(time_to_start_baller2(cf, data)) {
      cf_hc_baller_init(&ctx->ballers[1], cf, data);
    }

    if(cf_hc_baller_is_connecting(&ctx->ballers[1])) {
      result = cf_hc_baller_connect(&ctx->ballers[1], cf, data, done);
      if(!result && *done) {
        result = baller_connected(cf, data, &ctx->ballers[1]);
        goto out;
      }
    }

    if(ctx->ballers[0].result &&
       (ctx->ballers[1].result ||
        (ctx->ballers_complete && (ctx->baller_count < 2)))) {
      /* all have failed. we give up */
      CURL_TRC_CF(data, cf, "connect, all attempts failed");
      ctx->result = result = ctx->ballers[0].result;
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
    if(!cf_hc_baller_is_connecting(b) || b->shutdown)
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

static CURLcode cf_hc_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;
  if(!cf->connected) {
    struct cf_hc_ctx *ctx = cf->ctx;
    size_t i;

    for(i = 0; (i < ctx->baller_count) && !result; i++) {
      struct cf_hc_baller *b = &ctx->ballers[i];
      if(!cf_hc_baller_is_connecting(b))
        continue;
      result = Curl_conn_cf_adjust_pollset(b->cf, data, ps);
    }
    CURL_TRC_CF(data, cf, "adjust_pollset -> %d, %u socks", result, ps->n);
  }
  return result;
}

static bool cf_hc_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;
  size_t i;

  if(cf->connected)
    return cf->next->cft->has_data_pending(cf->next, data);

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
      if((t.tv_sec || t.tv_usec) && curlx_ptimediff_us(&t, &tmax) > 0)
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
  cf_hc_ctx_close(data, cf->ctx);
  cf->connected = FALSE;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static void cf_hc_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_hc_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  cf_hc_ctx_destroy(data, ctx);
}

struct Curl_cftype Curl_cft_http_connect = {
  "HTTPS-CONNECT",
  CF_TYPE_SETUP | CF_TYPE_HTTPSRR,
  CURL_LOG_LVL_NONE,
  cf_hc_destroy,
  cf_hc_connect,
  cf_hc_close,
  cf_hc_shutdown,
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
                             uint8_t def_transport)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_hc_ctx *ctx;
  CURLcode result = CURLE_OK;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->def_transport = def_transport;
  ctx->hard_eyeballs_timeout_ms = data->set.happy_eyeballs_timeout;
  ctx->soft_eyeballs_timeout_ms = data->set.happy_eyeballs_timeout / 2;

  result = Curl_cf_create(&cf, &Curl_cft_http_connect, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  *pcf = result ? NULL : cf;
  cf_hc_ctx_destroy(data, ctx);
  return result;
}

static CURLcode cf_hc_add(struct Curl_easy *data,
                          struct connectdata *conn,
                          int sockindex,
                          uint8_t def_transport)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_hc_create(&cf, data, def_transport);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

CURLcode Curl_cf_https_setup(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(conn->scheme->protocol == CURLPROTO_HTTPS);

  if((conn->scheme->protocol != CURLPROTO_HTTPS) ||
     !conn->bits.tls_enable_alpn)
     goto out;

  result = cf_hc_add(data, conn, sockindex, conn->transport_wanted);

out:
  return result;
}

#endif /* !CURL_DISABLE_HTTP */
