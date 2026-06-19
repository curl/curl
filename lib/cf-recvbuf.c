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

#ifndef CURL_DISABLE_WEBSOCKETS
/* only used for this protocol, so far */

#include "urldata.h"
#include "bufq.h"
#include "cfilters.h"
#include "cf-recvbuf.h"
#include "curl_trc.h"

#define CURL_CF_RECVBUF_CHUNK     (16 * 1024)

struct cf_recvbuf_ctx {
  struct bufq recvbuf;
};

static void cf_recvbuf_destroy(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_recvbuf_ctx *ctx = cf->ctx;
  (void)data;
  if(ctx) {
    Curl_bufq_free(&ctx->recvbuf);
    curlx_free(ctx);
  }
}

static CURLcode cf_recvbuf_recv(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len,
                                size_t *pnread)
{
  struct cf_recvbuf_ctx *ctx = cf->ctx;

  if(!Curl_bufq_is_empty(&ctx->recvbuf)) {
    return Curl_bufq_cread(&ctx->recvbuf, buf, len, pnread);
  }

  if(cf->next)
    return cf->next->cft->do_recv(cf->next, data, buf, len, pnread);
  *pnread = 0;
  return CURLE_RECV_ERROR;
}

static bool cf_recvbuf_data_pending(struct Curl_cfilter *cf,
                                    const struct Curl_easy *data)
{
  struct cf_recvbuf_ctx *ctx = cf->ctx;

  if(!Curl_bufq_is_empty(&ctx->recvbuf))
    return TRUE;

  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

struct Curl_cftype Curl_cft_recvbuf = {
  "RECVBUF",
  0,
  CURL_LOG_LVL_NONE,
  cf_recvbuf_destroy,
  Curl_cf_def_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  cf_recvbuf_data_pending,
  Curl_cf_def_send,
  cf_recvbuf_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_recvbuf_create(struct Curl_cfilter **pcf,
                                  struct Curl_easy *data,
                                  const uint8_t *buf, size_t blen)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_recvbuf_ctx *ctx;
  CURLcode result = CURLE_OK;
  size_t nwritten = 0;

  (void)data;
  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  Curl_bufq_init2(&ctx->recvbuf, CURL_CF_RECVBUF_CHUNK,
                  (blen / CURL_CF_RECVBUF_CHUNK) + 1,
                  (BUFQ_OPT_SOFT_LIMIT | BUFQ_OPT_NO_SPARES));
  result = Curl_bufq_write(&ctx->recvbuf, buf, blen, &nwritten);
  if(result)
    goto out;
  if(nwritten != blen) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_recvbuf, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  *pcf = result ? NULL : cf;
  if(ctx) {
    Curl_bufq_free(&ctx->recvbuf);
    curlx_free(ctx);
  }
  return result;
}

CURLcode Curl_cf_recvbuf_add(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             const uint8_t *buf, size_t blen)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_recvbuf_create(&cf, data, buf, blen);
  if(result)
    goto out;

  cf->connected = Curl_conn_is_connected(conn, sockindex);
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

#endif /* !CURL_DISABLE_WEBSOCKETS */
