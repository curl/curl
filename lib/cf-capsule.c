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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include <curl/curl.h>
#include "urldata.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "curlx/dynbuf.h"
#include "bufq.h"
#include "capsule.h"
#include "cf-capsule.h"

/* recv buffer: 4 chunks of 16KB = 64KB, enough for large datagrams */
#define CAPSULE_RECV_CHUNKS    4
#define CAPSULE_CHUNK_SIZE     (16 * 1024)

struct cf_capsule_ctx {
  struct bufq recvbuf;
  struct cf_call_data call_data;
  unsigned char *pending;       /* unsent capsule bytes from partial write */
  size_t pending_len;           /* total length of pending buffer */
  size_t pending_offset;        /* bytes already sent from pending */
  size_t pending_payload;       /* original payload len for pending capsule */
};

#define CF_CTX_CALL_DATA(cf) \
  ((struct cf_capsule_ctx *)(cf)->ctx)->call_data

static void capsule_cf_destroy(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_capsule_ctx *ctx = cf->ctx;
  (void)data;
  if(ctx) {
    Curl_bufq_free(&ctx->recvbuf);
    curlx_free(ctx->pending);
    curlx_free(ctx);
    cf->ctx = NULL;
  }
}

static void capsule_cf_close(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_capsule_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf->connected = FALSE;
  if(ctx) {
    Curl_bufq_reset(&ctx->recvbuf);
    curlx_free(ctx->pending);
    ctx->pending = NULL;
    ctx->pending_len = 0;
    ctx->pending_offset = 0;
    ctx->pending_payload = 0;
  }
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static CURLcode capsule_cf_connect(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *done)
{
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }
  if(cf->next) {
    CURLcode result = cf->next->cft->do_connect(cf->next, data, done);
    if(!result && *done)
      cf->connected = TRUE;
    return result;
  }
  *done = FALSE;
  return CURLE_OK;
}

static CURLcode capsule_cf_send(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const uint8_t *buf, size_t len,
                                bool eos, size_t *pnwritten)
{
  struct cf_capsule_ctx *ctx = cf->ctx;
  struct dynbuf dyn;
  size_t nwritten = 0;
  size_t capsule_len;
  size_t remaining;
  CURLcode result;

  (void)eos;
  *pnwritten = 0;

  if(ctx->pending) {
    /* flush remaining bytes from a partially sent capsule */
    remaining = ctx->pending_len - ctx->pending_offset;
    result = Curl_conn_cf_send(cf->next, data,
                               ctx->pending + ctx->pending_offset,
                               remaining, FALSE, &nwritten);
    if(result && result != CURLE_AGAIN) {
      curlx_free(ctx->pending);
      ctx->pending = NULL;
      return result;
    }
    ctx->pending_offset += nwritten;
    if(ctx->pending_offset < ctx->pending_len)
      return CURLE_AGAIN;
    /* pending capsule has been fully flusehd */
    *pnwritten = ctx->pending_payload;
    curlx_free(ctx->pending);
    ctx->pending = NULL;
    return CURLE_OK;
  }

  /* encapsulate new payload into a capsule */
  result = Curl_capsule_encap_udp_datagram(&dyn, buf, len);
  if(result) {
    curlx_dyn_free(&dyn);
    return result;
  }
  capsule_len = curlx_dyn_len(&dyn);

  result = Curl_conn_cf_send(cf->next, data,
                             (const uint8_t *)curlx_dyn_ptr(&dyn),
                             capsule_len, FALSE, &nwritten);
  if(result && result != CURLE_AGAIN) {
    curlx_dyn_free(&dyn);
    return result;
  }

  if(nwritten < capsule_len) {
    if(nwritten) {
      /* partial write - save unsent capsule bytes */
      remaining = capsule_len - nwritten;
      ctx->pending = curlx_malloc(remaining);
      if(!ctx->pending) {
        curlx_dyn_free(&dyn);
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(ctx->pending,
             curlx_dyn_ptr(&dyn) + nwritten, remaining);
      ctx->pending_len = remaining;
      ctx->pending_offset = 0;
      ctx->pending_payload = len;
    }
    curlx_dyn_free(&dyn);
    return CURLE_AGAIN;
  }

  /* entire capsule sent */
  curlx_dyn_free(&dyn);
  *pnwritten = len;
  return CURLE_OK;
}

static CURLcode capsule_cf_recv(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len,
                                size_t *pnread)
{
  struct cf_capsule_ctx *ctx = cf->ctx;
  CURLcode result;
  size_t nread;

  *pnread = 0;

  /* fill our receive buffer from the filter below */
  while(!Curl_bufq_is_full(&ctx->recvbuf)) {
    result = Curl_cf_recv_bufq(cf->next, data, &ctx->recvbuf, 0, &nread);
    if(result == CURLE_AGAIN)
      break;
    if(result)
      return result;
    if(!nread)
      break;
  }

  /* try to extract a complete capsule datagram */
  *pnread = Curl_capsule_process_udp_raw(cf, data, &ctx->recvbuf,
                                         (unsigned char *)buf, len,
                                         &result);
  return result;
}

static bool capsule_cf_data_pending(struct Curl_cfilter *cf,
                                    const struct Curl_easy *data)
{
  struct cf_capsule_ctx *ctx = cf->ctx;

  if(ctx && !Curl_bufq_is_empty(&ctx->recvbuf))
    return TRUE;
  return cf->next ? cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

struct Curl_cftype Curl_cft_capsule = {
  "CAPSULE",
  0,
  0,
  capsule_cf_destroy,
  capsule_cf_connect,
  capsule_cf_close,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  capsule_cf_data_pending,
  capsule_cf_send,
  capsule_cf_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

CURLcode Curl_cf_capsule_insert_after(struct Curl_cfilter *cf_at,
                                      struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  struct cf_capsule_ctx *ctx;
  CURLcode result;

  (void)data;
  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx)
    return CURLE_OUT_OF_MEMORY;

  Curl_bufq_init2(&ctx->recvbuf, CAPSULE_CHUNK_SIZE, CAPSULE_RECV_CHUNKS,
                   BUFQ_OPT_SOFT_LIMIT);

  result = Curl_cf_create(&cf, &Curl_cft_capsule, ctx);
  if(result) {
    Curl_bufq_free(&ctx->recvbuf);
    curlx_free(ctx);
    return result;
  }
  Curl_conn_cf_insert_after(cf_at, cf);
  return CURLE_OK;
}

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */
