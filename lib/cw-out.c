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


struct cw_out_ctx {
  struct Curl_cwriter super;
  struct dynbuf buf_body;
  struct dynbuf buf_hds;
  BIT(eos);
  BIT(paused_on_hds);
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
  struct cw_out_ctx *ctx = (struct cw_out_ctx *)writer;
  (void)data;
  Curl_dyn_init(&ctx->buf_body, DYN_PAUSE_BUFFER);
  Curl_dyn_init(&ctx->buf_hds, DYN_PAUSE_BUFFER);
  return CURLE_OK;
}

static void cw_out_close(struct Curl_easy *data, struct Curl_cwriter *writer)
{
  struct cw_out_ctx *ctx = (struct cw_out_ctx *)writer;

  (void)data;
  DEBUGF(infof(data, "cw_out_close(buf_hds=%zum, buf_body=%zu",
         Curl_dyn_len(&ctx->buf_hds), Curl_dyn_len(&ctx->buf_body)));
  Curl_dyn_free(&ctx->buf_body);
  Curl_dyn_free(&ctx->buf_hds);
}

static CURLcode cw_out_ptr_flush(struct cw_out_ctx *ctx,
                                 struct Curl_easy *data,
                                 curl_write_callback wcb,
                                 void *wcb_data,
                                 size_t chunk_max,
                                 size_t chunk_pref,
                                 bool flush_all,
                                 const char *buf, size_t blen,
                                 size_t *pconsumed)
{
  size_t wlen, nwritten;

  DEBUGASSERT(wcb);
  (void)ctx;
  *pconsumed = 0;
  while(blen) {
    if(!flush_all && blen < chunk_pref)
      break;
    wlen = CURLMIN(blen, chunk_max);
    nwritten = wcb((char *)buf, 1, wlen, wcb_data);
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
      break;
    }
    if(nwritten != wlen) {
      failf(data, "Failure writing output to destination");
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
                                 curl_write_callback wcb,
                                 void *wcb_data,
                                 size_t chunk_max,
                                 size_t chunk_pref,
                                 bool flush_all,
                                 struct dynbuf *buf)
{
  CURLcode result = CURLE_OK;

  if(Curl_dyn_len(buf)) {
    size_t consumed;
    result = cw_out_ptr_flush(ctx, data, wcb, wcb_data, chunk_max, chunk_pref,
                              flush_all, Curl_dyn_ptr(buf), Curl_dyn_len(buf),
                              &consumed);
    if(result)
      return result;
    if(consumed) {
      if(consumed == Curl_dyn_len(buf)) {
        Curl_dyn_free(buf);
      }
      else {
        DEBUGASSERT(consumed < Curl_dyn_len(buf));
        result = Curl_dyn_tail(buf, Curl_dyn_len(buf) - consumed);
        if(result)
          return result;
      }
    }
  }
  return result;
}

static CURLcode cw_out_do_write(struct cw_out_ctx *ctx,
                                struct Curl_easy *data,
                                curl_write_callback wcb,
                                void *wcb_data,
                                size_t chunk_max,
                                size_t chunk_pref, bool flush_all,
                                struct dynbuf *dest_buf,
                                const char *buf, size_t blen)
{
  CURLcode result;

  if(!wcb) {
    /* a client supplied callback might disappear, in which case
     * we clear `dest_buf` and return success */
    Curl_dyn_free(dest_buf);
    return CURLE_OK;
  }

  if(data->req.keepon & KEEP_RECV_PAUSE) {
    return Curl_dyn_addn(dest_buf, (unsigned char *)buf, blen);
  }
  ctx->paused_on_hds = FALSE;

  if(Curl_dyn_len(dest_buf) > chunk_max) {
    result = cw_out_buf_flush(ctx, data, wcb, wcb_data, chunk_max, chunk_pref,
                              flush_all, dest_buf);
    if(result)
      return result;
    if(data->req.keepon & KEEP_RECV_PAUSE) {
      /* flush did pause us */
      ctx->paused_on_hds = (dest_buf == &ctx->buf_hds);
      return Curl_dyn_addn(dest_buf, (unsigned char *)buf, blen);
    }
  }

  if(Curl_dyn_len(dest_buf)) {
  /* If something remained in the buffer, it is smaller than the chunk
   * size we'd like to write. Add the buffer and flush chunks again. */
    result = Curl_dyn_addn(dest_buf, (unsigned char *)buf, blen);
    if(result)
      return result;
    result = cw_out_buf_flush(ctx, data, wcb, wcb_data, chunk_max, chunk_pref,
                              flush_all||ctx->eos, dest_buf);
    if(result)
      return result;
  }
  else {
    /* `dest_buf` is empty, write `buf` directly out. This might not
     * consume all data when remainder is smaller than chunk_size (and EOS
     * is not set) or when the writing caused pausing. */
    size_t consumed;
    result = cw_out_ptr_flush(ctx, data, wcb, wcb_data, chunk_max, chunk_pref,
                              flush_all||ctx->eos, buf, blen, &consumed);
    if(result)
      return result;
    DEBUGASSERT(consumed <= blen);
    blen -= consumed;
    buf += consumed;
    if(blen) {
      result = Curl_dyn_addn(dest_buf, (unsigned char *)buf, blen);
      if(result)
        return result;
    }
  }

  if(data->req.keepon & KEEP_RECV_PAUSE) {
    ctx->paused_on_hds = (dest_buf == &ctx->buf_hds);
  }

  return CURLE_OK;
}

static CURLcode cw_out_write_body(struct cw_out_ctx *ctx,
                                  struct Curl_easy *data, bool flush_all,
                                  const char *buf, size_t blen)
{
  /* For header write callbacks, the chunk size is CURL_MAX_WRITE_SIZE
   * and we may collate smaller writes to that size, depending on
   * protocol spoken. */
  size_t chunk_pref = (data->conn &&
                       (data->conn->handler->protocol & PROTO_FAMILY_HTTP))?
                       CURL_MAX_WRITE_SIZE/2 : 0;
  DEBUGF(infof(data, "cw_out_write_body(len=%zu), buffered=%zu, eos=%d",
               blen, Curl_dyn_len(&ctx->buf_body), ctx->eos));
  return cw_out_do_write(ctx, data, data->set.fwrite_func, data->set.out,
                         CURL_MAX_WRITE_SIZE, chunk_pref, flush_all,
                         &ctx->buf_body, buf, blen);
}

static CURLcode cw_out_write_hds(struct cw_out_ctx *ctx,
                                 struct Curl_easy *data, bool flush_all,
                                 const char *buf, size_t blen)
{
  /* For header write callbacks, the chunk size is CURL_MAX_HTTP_HEADER
   * and we write immmediately also small amounts. */
  DEBUGF(infof(data, "cw_out_write_hds(len=%zu), buffered=%zu, eos=%d",
               blen, Curl_dyn_len(&ctx->buf_hds), ctx->eos));
  /* Write headers, but before we do that, we flush any pending
   * BODY data if a pause was not caused by writeing hds */
  if(!ctx->paused_on_hds && Curl_dyn_len(&ctx->buf_body)) {
    CURLcode result = cw_out_write_body(ctx, data, TRUE, buf, 0);
    if(result)
      return result;
  }
  return cw_out_do_write(ctx, data, data->set.fwrite_header?
                         data->set.fwrite_header:
                         (data->set.writeheader? data->set.fwrite_func:NULL),
                         data->set.writeheader, CURL_MAX_HTTP_HEADER, 0,
                         flush_all, &ctx->buf_hds, buf, blen);
}

static CURLcode cw_out_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t blen)
{
  struct cw_out_ctx *ctx = (struct cw_out_ctx *)writer;
  CURLcode result;

#ifndef CURL_DISABLE_HTTP
  /* HTTP header, but not status-line */
  if(data->conn && (data->conn->handler->protocol & PROTO_FAMILY_HTTP) &&
     (type & CLIENTWRITE_HEADER) && !(type & CLIENTWRITE_STATUS) ) {
    unsigned char htype = (unsigned char)
      (type & CLIENTWRITE_CONNECT ? CURLH_CONNECT :
       (type & CLIENTWRITE_1XX ? CURLH_1XX :
        (type & CLIENTWRITE_TRAILER ? CURLH_TRAILER :
         CURLH_HEADER)));
    result = Curl_headers_push(data, buf, htype);
    if(result)
      return result;
  }
#endif

  if(type & CLIENTWRITE_EOS)
    ctx->eos = TRUE;

  if((type & CLIENTWRITE_BODY) ||
     ((type & CLIENTWRITE_HEADER) && data->set.include_header)) {
    result = cw_out_write_body(ctx, data, FALSE, buf, blen);
    if(result)
      return result;
  }

  if(type & (CLIENTWRITE_HEADER|CLIENTWRITE_INFO)) {
    result = cw_out_write_hds(ctx, data, FALSE, buf, blen);
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
  return Curl_dyn_len(&ctx->buf_body) || Curl_dyn_len(&ctx->buf_hds);
}

static CURLcode cw_out_flush(struct Curl_easy *data, bool eos)
{
  struct Curl_cwriter *cw_out;
  CURLcode result = CURLE_OK;
  char tmp[1];

  cw_out = Curl_cwriter_get_by_type(data, &Curl_cwt_out);
  if(cw_out) {
    struct cw_out_ctx *ctx = (struct cw_out_ctx *)cw_out;

    if(eos)
      ctx->eos = TRUE;

    if(ctx->paused_on_hds) {
      result = cw_out_write_hds(ctx, data, eos, tmp, 0);
    }
    if(!result && Curl_dyn_len(&ctx->buf_body)) {
      result = cw_out_write_body(ctx, data, eos, tmp, 0);
    }
    if(!result && Curl_dyn_len(&ctx->buf_hds)) {
      result = cw_out_write_hds(ctx, data, eos, tmp, 0);
    }
  }
  return result;
}

CURLcode Curl_cw_out_flush(struct Curl_easy *data)
{
  return cw_out_flush(data, FALSE);
}

CURLcode Curl_cw_out_done(struct Curl_easy *data)
{
  return cw_out_flush(data, TRUE);
}
