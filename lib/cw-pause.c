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

#include "urldata.h"
#include "cfilters.h"
#include "headers.h"
#include "multiif.h"
#include "sendf.h"
#include "cw-pause.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define CW_PAUSE_BODY_CHUNK    (128 * 1024)

struct cw_pause_buf {
  struct cw_pause_buf *next;
  struct dynbuf b;
  int type;
};

static struct cw_pause_buf *cw_pause_buf_create(int type, size_t buflen)
{
  struct cw_pause_buf *cwbuf = calloc(1, sizeof(*cwbuf));
  if(cwbuf) {
    cwbuf->type = type;
    Curl_dyn_init(&cwbuf->b, buflen + 1); /* dynbuf always adds a NUL */
  }
  return cwbuf;
}

static void cw_pause_buf_free(struct cw_pause_buf *cwbuf)
{
  if(cwbuf) {
    Curl_dyn_free(&cwbuf->b);
    free(cwbuf);
  }
}

struct cw_pause_ctx {
  struct Curl_cwriter super;
  struct cw_pause_buf *buf;
  size_t buf_total;
};

static CURLcode cw_pause_write(struct Curl_easy *data,
                               struct Curl_cwriter *writer, int type,
                               const char *buf, size_t nbytes);
static void cw_pause_close(struct Curl_easy *data,
                           struct Curl_cwriter *writer);
static CURLcode cw_pause_init(struct Curl_easy *data,
                              struct Curl_cwriter *writer);

struct Curl_cwtype Curl_cwt_pause = {
  "cw-pause",
  NULL,
  cw_pause_init,
  cw_pause_write,
  cw_pause_close,
  sizeof(struct cw_pause_ctx)
};

static CURLcode cw_pause_init(struct Curl_easy *data,
                              struct Curl_cwriter *writer)
{
  struct cw_pause_ctx *ctx = writer->ctx;
  (void)data;
  ctx->buf = NULL;
  return CURLE_OK;
}

static void cw_pause_bufs_free(struct cw_pause_ctx *ctx)
{
  while(ctx->buf) {
    struct cw_pause_buf *next = ctx->buf->next;
    cw_pause_buf_free(ctx->buf);
    ctx->buf = next;
  }
}

static void cw_pause_close(struct Curl_easy *data, struct Curl_cwriter *writer)
{
  struct cw_pause_ctx *ctx = writer->ctx;

  (void)data;
  cw_pause_bufs_free(ctx);
}

static CURLcode cw_pause_flush(struct Curl_easy *data,
                               struct Curl_cwriter *cw_pause)
{
  struct cw_pause_ctx *ctx = (struct cw_pause_ctx *)cw_pause;
  CURLcode result = CURLE_OK;

  /* write the end of the chain until it blocks or gets empty */
  while(ctx->buf && !Curl_cwriter_is_paused(data)) {
    struct cw_pause_buf **plast = &ctx->buf;
    size_t wlen = 0;
    while((*plast)->next) /* got to last in list */
      plast = &(*plast)->next;
    wlen = Curl_dyn_len(&(*plast)->b);
    result = Curl_cwriter_write(data, cw_pause->next, (*plast)->type,
                                Curl_dyn_ptr(&(*plast)->b), wlen);
    CURL_TRC_WRITE(data, "[PAUSE] flushed %zu/%zu bytes, type=%x -> %d",
                   wlen, ctx->buf_total, (*plast)->type, result);
    if(result)
      return result;
    cw_pause_buf_free(*plast);
    DEBUGASSERT(ctx->buf_total >= wlen);
    ctx->buf_total -= wlen;
    *plast = NULL;
  }
  return result;
}

static CURLcode cw_pause_write(struct Curl_easy *data,
                               struct Curl_cwriter *writer, int type,
                               const char *buf, size_t blen)
{
  struct cw_pause_ctx *ctx = writer->ctx;
  CURLcode result = CURLE_OK;

  if(!Curl_cwriter_is_paused(data) && ctx->buf) {
    /* try to flush */
    result = cw_pause_flush(data, writer);
    if(result)
      return result;
  }

  if(!Curl_cwriter_is_paused(data)) {
    DEBUGASSERT(!ctx->buf);
    return Curl_cwriter_write(data, writer->next, type, buf, blen);
  }

  do {
    size_t wlen = 0;
    /* prepend to ctx->buf list */
    if(ctx->buf && (ctx->buf->type == type) && (type & CLIENTWRITE_BODY) &&
       Curl_dyn_left(&ctx->buf->b)) {
      /* same type and body, append to current buffer as much as we can */
      wlen = CURLMIN(blen, Curl_dyn_left(&ctx->buf->b));
      result = Curl_dyn_addn(&ctx->buf->b, buf, wlen);
    }
    else {
      /* Need new buf(s) */
      size_t clen = (type & CLIENTWRITE_BODY) ? CW_PAUSE_BODY_CHUNK : blen;
      struct cw_pause_buf *cwbuf = cw_pause_buf_create(type, clen);
      if(!cwbuf)
        return CURLE_OUT_OF_MEMORY;
      cwbuf->next = ctx->buf;
      ctx->buf = cwbuf;
      wlen = CURLMIN(blen, Curl_dyn_left(&ctx->buf->b));
      result = Curl_dyn_addn(&ctx->buf->b, buf, wlen);
    }
    CURL_TRC_WRITE(data, "[PAUSE] buffer %zu more bytes of type %x, "
                   "total=%zu -> %d", wlen, type, ctx->buf_total + wlen,
                   result);
    if(result)
      return result;
    buf += wlen;
    blen -= wlen;
    ctx->buf_total += wlen;
  } while(blen);

  return result;
}

CURLcode Curl_cw_pause_flush(struct Curl_easy *data)
{
  struct Curl_cwriter *cw_pause;
  CURLcode result = CURLE_OK;

  cw_pause = Curl_cwriter_get_by_type(data, &Curl_cwt_pause);
  if(cw_pause)
    result = cw_pause_flush(data, cw_pause);

  return result;
}
