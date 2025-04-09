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
#include "bufq.h"
#include "cfilters.h"
#include "headers.h"
#include "multiif.h"
#include "sendf.h"
#include "cw-pause.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


/* body dynbuf sizes */
#define CW_PAUSE_BUF_CHUNK         (16 * 1024)
/* when content decoding, write data in chunks */
#define CW_PAUSE_DEC_WRITE_CHUNK   (4096)

struct cw_pause_buf {
  struct cw_pause_buf *next;
  struct bufq b;
  int type;
};

static struct cw_pause_buf *cw_pause_buf_create(int type, size_t buflen)
{
  struct cw_pause_buf *cwbuf = calloc(1, sizeof(*cwbuf));
  if(cwbuf) {
    cwbuf->type = type;
    if(type & CLIENTWRITE_BODY)
      Curl_bufq_init2(&cwbuf->b, CW_PAUSE_BUF_CHUNK, 1,
                      (BUFQ_OPT_SOFT_LIMIT|BUFQ_OPT_NO_SPARES));
    else
      Curl_bufq_init(&cwbuf->b, buflen, 1);
  }
  return cwbuf;
}

static void cw_pause_buf_free(struct cw_pause_buf *cwbuf)
{
  if(cwbuf) {
    Curl_bufq_free(&cwbuf->b);
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

const struct Curl_cwtype Curl_cwt_pause = {
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
  bool decoding = Curl_cwriter_is_content_decoding(data);
  CURLcode result = CURLE_OK;

  /* write the end of the chain until it blocks or gets empty */
  while(ctx->buf && !Curl_cwriter_is_paused(data)) {
    struct cw_pause_buf **plast = &ctx->buf;
    size_t blen, wlen = 0;
    const unsigned char *buf = NULL;

    while((*plast)->next) /* got to last in list */
      plast = &(*plast)->next;
    if(Curl_bufq_peek(&(*plast)->b, &buf, &blen)) {
      wlen = (decoding && ((*plast)->type & CLIENTWRITE_BODY)) ?
             CURLMIN(blen, CW_PAUSE_DEC_WRITE_CHUNK) : blen;
      result = Curl_cwriter_write(data, cw_pause->next, (*plast)->type,
                                  (const char *)buf, wlen);
      CURL_TRC_WRITE(data, "[PAUSE] flushed %zu/%zu bytes, type=%x -> %d",
                     wlen, ctx->buf_total, (*plast)->type, result);
      Curl_bufq_skip(&(*plast)->b, wlen);
      DEBUGASSERT(ctx->buf_total >= wlen);
      ctx->buf_total -= wlen;
      if(result)
        return result;
    }
    else if((*plast)->type & CLIENTWRITE_EOS) {
      result = Curl_cwriter_write(data, cw_pause->next, (*plast)->type,
                                  (const char *)buf, 0);
      CURL_TRC_WRITE(data, "[PAUSE] flushed 0/%zu bytes, type=%x -> %d",
                     ctx->buf_total, (*plast)->type, result);
    }

    if(Curl_bufq_is_empty(&(*plast)->b)) {
      cw_pause_buf_free(*plast);
      *plast = NULL;
    }
  }
  return result;
}

static CURLcode cw_pause_write(struct Curl_easy *data,
                               struct Curl_cwriter *writer, int type,
                               const char *buf, size_t blen)
{
  struct cw_pause_ctx *ctx = writer->ctx;
  CURLcode result = CURLE_OK;
  size_t wlen = 0;
  bool decoding = Curl_cwriter_is_content_decoding(data);

  if(ctx->buf && !Curl_cwriter_is_paused(data)) {
    result = cw_pause_flush(data, writer);
    if(result)
      return result;
  }

  while(!ctx->buf && !Curl_cwriter_is_paused(data)) {
    int wtype = type;
    DEBUGASSERT(!ctx->buf);
    /* content decoding might blow up size considerably, write smaller
     * chunks to make pausing need buffer less. */
    wlen = (decoding && (type & CLIENTWRITE_BODY)) ?
           CURLMIN(blen, CW_PAUSE_DEC_WRITE_CHUNK) : blen;
    if(wlen < blen)
      wtype &= ~CLIENTWRITE_EOS;
    result = Curl_cwriter_write(data, writer->next, wtype, buf, wlen);
    CURL_TRC_WRITE(data, "[PAUSE] writing %zu/%zu bytes of type %x -> %d",
                   wlen, blen, wtype, result);
    if(result)
      return result;
    buf += wlen;
    blen -= wlen;
    if(!blen)
      return result;
  }

  do {
    size_t nwritten = 0;
    if(ctx->buf && (ctx->buf->type == type) && (type & CLIENTWRITE_BODY)) {
      /* same type and body, append to current buffer which has a soft
       * limit and should take everything up to OOM. */
      result = Curl_bufq_cwrite(&ctx->buf->b, buf, blen, &nwritten);
    }
    else {
      /* Need a new buf, type changed */
      struct cw_pause_buf *cwbuf = cw_pause_buf_create(type, blen);
      if(!cwbuf)
        return CURLE_OUT_OF_MEMORY;
      cwbuf->next = ctx->buf;
      ctx->buf = cwbuf;
      result = Curl_bufq_cwrite(&ctx->buf->b, buf, blen, &nwritten);
    }
    CURL_TRC_WRITE(data, "[PAUSE] buffer %zu more bytes of type %x, "
                   "total=%zu -> %d", nwritten, type, ctx->buf_total + wlen,
                   result);
    if(result)
      return result;
    buf += nwritten;
    blen -= nwritten;
    ctx->buf_total += nwritten;
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
