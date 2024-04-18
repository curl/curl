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
#include "cw-out.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


/**
 * OVERALL DESIGN of this client writer
 *
 * The 'cw-out' writer is supposed to be the last writer in a transfer's
 * stack. It is always added when that stack is initialized. Its purpose
 * is to pass BODY and HEADER bytes to the client-installed callback
 * functions.
 *
 * These callback may return `CURL_WRITEFUNC_PAUSE` to indicate that the
 * data had not been written and the whole transfer should stop receiving
 * new data. Or at least, stop calling the functions. When the transfer
 * is "unpaused" by the client, the previous data shall be passed as
 * if nothing happened.
 *
 * The `cw-out` writer therefore manages buffers for bytes that could
 * not be written. Data that was already in flight from the server also
 * needs buffering on paused transfer when it arrives.
 *
 * In addition, the writer allows buffering of "small" body writes,
 * so client functions are called less often. That is only enabled on a
 * number of conditions.
 *
 * HEADER and BODY data may arrive in any order. For paused transfers,
 * a list of `struct cw_out_buf` is kept for `cw_out_type` types. The
 * list may be: [BODY]->[HEADER]->[BODY]->[HEADER]....
 * When unpausing, this list is "played back" to the client callbacks.
 *
 * The amount of bytes being buffered is limited by `DYN_PAUSE_BUFFER`
 * and when that is exceeded `CURLE_TOO_LARGE` is returned as error.
 */
typedef enum {
  CW_OUT_NONE,
  CW_OUT_BODY,
  CW_OUT_HDS
} cw_out_type;

struct cw_out_buf {
  struct cw_out_buf *next;
  struct dynbuf b;
  cw_out_type type;
};

static struct cw_out_buf *cw_out_buf_create(cw_out_type otype)
{
  struct cw_out_buf *cwbuf = calloc(1, sizeof(*cwbuf));
  if(cwbuf) {
    cwbuf->type = otype;
    Curl_dyn_init(&cwbuf->b, DYN_PAUSE_BUFFER);
  }
  return cwbuf;
}

static void cw_out_buf_free(struct cw_out_buf *cwbuf)
{
  if(cwbuf) {
    Curl_dyn_free(&cwbuf->b);
    free(cwbuf);
  }
}

struct cw_out_ctx {
  struct Curl_cwriter super;
  struct cw_out_buf *buf;
  BIT(paused);
  BIT(errored);
};

static CURLcode cw_out_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes);
static void cw_out_close(struct Curl_easy *data, struct Curl_cwriter *writer);
static CURLcode cw_out_init(struct Curl_easy *data,
                            struct Curl_cwriter *writer);

struct Curl_cwtype Curl_cwt_out = {
  "cw-out",
  NULL,
  cw_out_init,
  cw_out_write,
  cw_out_close,
  sizeof(struct cw_out_ctx)
};

static CURLcode cw_out_init(struct Curl_easy *data,
                            struct Curl_cwriter *writer)
{
  struct cw_out_ctx *ctx = writer->ctx;
  (void)data;
  ctx->buf = NULL;
  return CURLE_OK;
}

static void cw_out_bufs_free(struct cw_out_ctx *ctx)
{
  while(ctx->buf) {
    struct cw_out_buf *next = ctx->buf->next;
    cw_out_buf_free(ctx->buf);
    ctx->buf = next;
  }
}

static size_t cw_out_bufs_len(struct cw_out_ctx *ctx)
{
  struct cw_out_buf *cwbuf = ctx->buf;
  size_t len = 0;
  while(cwbuf) {
    len += Curl_dyn_len(&cwbuf->b);
    cwbuf = cwbuf->next;
  }
  return len;
}

static void cw_out_close(struct Curl_easy *data, struct Curl_cwriter *writer)
{
  struct cw_out_ctx *ctx = writer->ctx;

  (void)data;
  cw_out_bufs_free(ctx);
}

/**
 * Return the current curl_write_callback and user_data for the buf type
 */
static void cw_get_writefunc(struct Curl_easy *data, cw_out_type otype,
                             curl_write_callback *pwcb, void **pwcb_data,
                             size_t *pmax_write, size_t *pmin_write)
{
  switch(otype) {
  case CW_OUT_BODY:
    *pwcb = data->set.fwrite_func;
    *pwcb_data = data->set.out;
    *pmax_write = CURL_MAX_WRITE_SIZE;
    /* if we ever want buffering of BODY output, we can set `min_write`
     * the preferred size. The default should always be to pass data
     * to the client as it comes without delay */
    *pmin_write = 0;
    break;
  case CW_OUT_HDS:
    *pwcb = data->set.fwrite_header? data->set.fwrite_header :
             (data->set.writeheader? data->set.fwrite_func : NULL);
    *pwcb_data = data->set.writeheader;
    *pmax_write = 0; /* do not chunk-write headers, write them as they are */
    *pmin_write = 0;
    break;
  default:
    *pwcb = NULL;
    *pwcb_data = NULL;
    *pmax_write = CURL_MAX_WRITE_SIZE;
    *pmin_write = 0;
  }
}

static CURLcode cw_out_ptr_flush(struct cw_out_ctx *ctx,
                                 struct Curl_easy *data,
                                 cw_out_type otype,
                                 bool flush_all,
                                 const char *buf, size_t blen,
                                 size_t *pconsumed)
{
  curl_write_callback wcb;
  void *wcb_data;
  size_t max_write, min_write;
  size_t wlen, nwritten;

  /* If we errored once, we do not invoke the client callback  again */
  if(ctx->errored)
    return CURLE_WRITE_ERROR;

  /* write callbacks may get NULLed by the client between calls. */
  cw_get_writefunc(data, otype, &wcb, &wcb_data, &max_write, &min_write);
  if(!wcb) {
    *pconsumed = blen;
    return CURLE_OK;
  }

  *pconsumed = 0;
  while(blen && !ctx->paused) {
    if(!flush_all && blen < min_write)
      break;
    wlen = max_write? CURLMIN(blen, max_write) : blen;
    Curl_set_in_callback(data, TRUE);
    nwritten = wcb((char *)buf, 1, wlen, wcb_data);
    Curl_set_in_callback(data, FALSE);
    CURL_TRC_WRITE(data, "cw_out, wrote %zu %s bytes -> %zu",
                   wlen, (otype == CW_OUT_BODY)? "body" : "header",
                   nwritten);
    if(CURL_WRITEFUNC_PAUSE == nwritten) {
      if(data->conn && data->conn->handler->flags & PROTOPT_NONETWORK) {
        /* Protocols that work without network cannot be paused. This is
           actually only FILE:// just now, and it can't pause since the
           transfer isn't done using the "normal" procedure. */
        failf(data, "Write callback asked for PAUSE when not supported");
        return CURLE_WRITE_ERROR;
      }
      /* mark the connection as RECV paused */
      data->req.keepon |= KEEP_RECV_PAUSE;
      ctx->paused = TRUE;
      CURL_TRC_WRITE(data, "cw_out, PAUSE requested by client");
      break;
    }
    else if(CURL_WRITEFUNC_ERROR == nwritten) {
      failf(data, "client returned ERROR on write of %zu bytes", wlen);
      return CURLE_WRITE_ERROR;
    }
    else if(nwritten != wlen) {
      failf(data, "Failure writing output to destination, "
            "passed %zu returned %zd", wlen, nwritten);
      return CURLE_WRITE_ERROR;
    }
    *pconsumed += nwritten;
    blen -= nwritten;
    buf += nwritten;
  }
  return CURLE_OK;
}

static CURLcode cw_out_buf_flush(struct cw_out_ctx *ctx,
                                 struct Curl_easy *data,
                                 struct cw_out_buf *cwbuf,
                                 bool flush_all)
{
  CURLcode result = CURLE_OK;

  if(Curl_dyn_len(&cwbuf->b)) {
    size_t consumed;

    result = cw_out_ptr_flush(ctx, data, cwbuf->type, flush_all,
                              Curl_dyn_ptr(&cwbuf->b),
                              Curl_dyn_len(&cwbuf->b),
                              &consumed);
    if(result)
      return result;

    if(consumed) {
      if(consumed == Curl_dyn_len(&cwbuf->b)) {
        Curl_dyn_free(&cwbuf->b);
      }
      else {
        DEBUGASSERT(consumed < Curl_dyn_len(&cwbuf->b));
        result = Curl_dyn_tail(&cwbuf->b, Curl_dyn_len(&cwbuf->b) - consumed);
        if(result)
          return result;
      }
    }
  }
  return result;
}

static CURLcode cw_out_flush_chain(struct cw_out_ctx *ctx,
                                   struct Curl_easy *data,
                                   struct cw_out_buf **pcwbuf,
                                   bool flush_all)
{
  struct cw_out_buf *cwbuf = *pcwbuf;
  CURLcode result;

  if(!cwbuf)
    return CURLE_OK;
  if(ctx->paused)
    return CURLE_OK;

  /* write the end of the chain until it blocks or gets empty */
  while(cwbuf->next) {
    struct cw_out_buf **plast = &cwbuf->next;
    while((*plast)->next)
      plast = &(*plast)->next;
    result = cw_out_flush_chain(ctx, data, plast, flush_all);
    if(result)
      return result;
    if(*plast) {
      /* could not write last, paused again? */
      DEBUGASSERT(ctx->paused);
      return CURLE_OK;
    }
  }

  result = cw_out_buf_flush(ctx, data, cwbuf, flush_all);
  if(result)
    return result;
  if(!Curl_dyn_len(&cwbuf->b)) {
    cw_out_buf_free(cwbuf);
    *pcwbuf = NULL;
  }
  return CURLE_OK;
}

static CURLcode cw_out_append(struct cw_out_ctx *ctx,
                              cw_out_type otype,
                              const char *buf, size_t blen)
{
  if(cw_out_bufs_len(ctx) + blen > DYN_PAUSE_BUFFER)
    return CURLE_TOO_LARGE;

  /* if we do not have a buffer, or it is of another type, make a new one.
   * And for CW_OUT_HDS always make a new one, so we "replay" headers
   * exactly as they came in */
  if(!ctx->buf || (ctx->buf->type != otype) || (otype == CW_OUT_HDS)) {
    struct cw_out_buf *cwbuf = cw_out_buf_create(otype);
    if(!cwbuf)
      return CURLE_OUT_OF_MEMORY;
    cwbuf->next = ctx->buf;
    ctx->buf = cwbuf;
  }
  DEBUGASSERT(ctx->buf && (ctx->buf->type == otype));
  return Curl_dyn_addn(&ctx->buf->b, buf, blen);
}

static CURLcode cw_out_do_write(struct cw_out_ctx *ctx,
                                struct Curl_easy *data,
                                cw_out_type otype,
                                bool flush_all,
                                const char *buf, size_t blen)
{
  CURLcode result = CURLE_OK;

  /* if we have buffered data and it is a different type than what
   * we are writing now, try to flush all */
  if(ctx->buf && ctx->buf->type != otype) {
    result = cw_out_flush_chain(ctx, data, &ctx->buf, TRUE);
    if(result)
      goto out;
  }

  if(ctx->buf) {
    /* still have buffered data, append and flush */
    result = cw_out_append(ctx, otype, buf, blen);
    if(result)
      return result;
    result = cw_out_flush_chain(ctx, data, &ctx->buf, flush_all);
    if(result)
      goto out;
  }
  else {
    /* nothing buffered, try direct write */
    size_t consumed;
    result = cw_out_ptr_flush(ctx, data, otype, flush_all,
                              buf, blen, &consumed);
    if(result)
      return result;
    if(consumed < blen) {
      /* did not write all, append the rest */
      result = cw_out_append(ctx, otype, buf + consumed, blen - consumed);
      if(result)
        goto out;
    }
  }

out:
  if(result) {
    /* We do not want to invoked client callbacks a second time after
     * encountering an error. See issue #13337 */
    ctx->errored = TRUE;
    cw_out_bufs_free(ctx);
  }
  return result;
}

static CURLcode cw_out_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t blen)
{
  struct cw_out_ctx *ctx = writer->ctx;
  CURLcode result;
  bool flush_all;

  flush_all = (type & CLIENTWRITE_EOS)? TRUE:FALSE;
  if((type & CLIENTWRITE_BODY) ||
     ((type & CLIENTWRITE_HEADER) && data->set.include_header)) {
    result = cw_out_do_write(ctx, data, CW_OUT_BODY, flush_all, buf, blen);
    if(result)
      return result;
  }

  if(type & (CLIENTWRITE_HEADER|CLIENTWRITE_INFO)) {
    result = cw_out_do_write(ctx, data, CW_OUT_HDS, flush_all, buf, blen);
    if(result)
      return result;
  }

  return CURLE_OK;
}

bool Curl_cw_out_is_paused(struct Curl_easy *data)
{
  struct Curl_cwriter *cw_out;
  struct cw_out_ctx *ctx;

  cw_out = Curl_cwriter_get_by_type(data, &Curl_cwt_out);
  if(!cw_out)
    return FALSE;

  ctx = (struct cw_out_ctx *)cw_out;
  CURL_TRC_WRITE(data, "cw-out is%spaused", ctx->paused? "" : " not");
  return ctx->paused;
}

static CURLcode cw_out_flush(struct Curl_easy *data,
                             bool unpause, bool flush_all)
{
  struct Curl_cwriter *cw_out;
  CURLcode result = CURLE_OK;

  cw_out = Curl_cwriter_get_by_type(data, &Curl_cwt_out);
  if(cw_out) {
    struct cw_out_ctx *ctx = (struct cw_out_ctx *)cw_out;
    if(ctx->errored)
      return CURLE_WRITE_ERROR;
    if(unpause && ctx->paused)
      ctx->paused = FALSE;
    if(ctx->paused)
      return CURLE_OK;  /* not doing it */

    result = cw_out_flush_chain(ctx, data, &ctx->buf, flush_all);
    if(result) {
      ctx->errored = TRUE;
      cw_out_bufs_free(ctx);
      return result;
    }
  }
  return result;
}

CURLcode Curl_cw_out_unpause(struct Curl_easy *data)
{
  CURL_TRC_WRITE(data, "cw-out unpause");
  return cw_out_flush(data, TRUE, FALSE);
}

CURLcode Curl_cw_out_done(struct Curl_easy *data)
{
  CURL_TRC_WRITE(data, "cw-out done");
  return cw_out_flush(data, FALSE, TRUE);
}
