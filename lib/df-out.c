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

#include "urldata.h"
#include <curl/curl.h>
#include <stddef.h>

#include "curl_trc.h"
#include "cfilters.h"
#include "dfilters.h"
#include "df-out.h"
#include "headers.h"
#include "http.h"
#include "multiif.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

struct paused_write {
  struct dynbuf b;
  int meta_type;
};

struct df_out_writer_ctx {
  struct Curl_df_writer super;
  struct paused_write paused[3];
  size_t npaused;
};

static CURLcode df_out_init(struct Curl_df_writer *writer,
                            struct Curl_easy *data)
{
  struct df_out_writer_ctx *ctx = (struct df_out_writer_ctx *)writer;
  (void)data;
  ctx->npaused = 0;
  return CURLE_OK;
}

static ssize_t do_write(struct Curl_easy *data, int meta_type,
                        const char *buf, size_t blen, CURLcode *err)
{
  size_t wlen, chunk_size = 0;
  ssize_t nwritten = 0;
  bool is_body = (meta_type == DF_WRITE_BODY);
  curl_write_callback write_cb = NULL;
  void *cb_user_data = NULL;

  *err = CURLE_OK;
  if(!blen || (is_body && data->req.ignorebody)) {
    nwritten = (ssize_t)blen;
    goto out;
  }

  if(is_body) {
#ifdef USE_WEBSOCKETS
    if(data->conn->handler->protocol & (CURLPROTO_WS|CURLPROTO_WSS)) {
      write_cb = Curl_ws_writecb;
      cb_user_data = data;
    }
    else
#endif
    {
      write_cb = data->set.fwrite_func;
      cb_user_data = data->set.out;
    }
    chunk_size = CURL_MAX_WRITE_SIZE;
  }
  else if(data->set.fwrite_header || data->set.writeheader) {
    /*
     * Write headers to the same callback or to the especially setup
     * header callback function (added after version 7.7.1).
     */
    write_cb =
      data->set.fwrite_header? data->set.fwrite_header: data->set.fwrite_func;
    cb_user_data = data->set.writeheader;
  }

  if(!write_cb) {
    nwritten = (ssize_t)blen;
    goto out;
  }

  while(blen) {
    size_t wrote;
    if(data->req.keepon & KEEP_RECV_PAUSE) {
      *err = CURLE_OK;
      goto out;
    }

    wlen = (chunk_size && blen > chunk_size)? chunk_size : blen;
    Curl_set_in_callback(data, true);
    wrote = write_cb((char *)buf, 1, wlen, cb_user_data);
    Curl_set_in_callback(data, false);

    if(CURL_WRITEFUNC_PAUSE == wrote) {
      if(data->conn->handler->flags & PROTOPT_NONETWORK) {
        /* Protocols that work without network cannot be paused. This is
           actually only FILE:// just now, and it can't pause since the
           transfer isn't done using the "normal" procedure. */
        failf(data, "Write callback asked for PAUSE when not supported");
        *err = CURLE_WRITE_ERROR;
        nwritten = -1;
        goto out;
      }
      *err = CURLE_OK;
      goto out;
    }
    else if(wrote != wlen) {
      failf(data, "Failure writing output to destination");
      *err = CURLE_WRITE_ERROR;
      nwritten = -1;
      goto out;
    }
    DEBUGASSERT(wlen <= blen);
    blen -= wlen;
    buf += wlen;
    nwritten += wlen;
  }

out:
  return nwritten;
}

static CURLcode df_out_pause(struct Curl_df_writer *writer,
                             struct Curl_easy *data,
                             int meta_type,
                             const char *buf, size_t blen)
{
  struct df_out_writer_ctx *ctx = (struct df_out_writer_ctx *)writer;
  size_t i = 0;

  Curl_conn_ev_data_pause(data, TRUE);

  for(i = 0; i < ctx->npaused; i++) {
    if(ctx->paused[i].meta_type == meta_type) {
      /* data for this type exists */
      break;
    }
  }

  if(i >= ctx->npaused) {
    /* none exist or match, add another if there is still one left */
    DEBUGASSERT(i < ARRAYSIZE(ctx->paused));
    if(i >= ARRAYSIZE(ctx->paused))
      return CURLE_OUT_OF_MEMORY;
    Curl_dyn_init(&ctx->paused[i].b, DYN_PAUSE_BUFFER);
    ctx->paused[i].meta_type = meta_type;
    ctx->npaused = i + 1;
  }

  if(Curl_dyn_addn(&ctx->paused[i].b, (unsigned char *)buf, blen))
    return CURLE_OUT_OF_MEMORY;

  /* mark the connection as RECV paused */
  data->req.keepon |= KEEP_RECV_PAUSE;

  return CURLE_OK;
}

static CURLcode df_out_do_meta(struct Curl_df_writer *writer,
                               struct Curl_easy *data, int meta_type,
                               const char *buf, size_t blen)
{
  CURLcode result = CURLE_OK;
  ssize_t nwritten;

  /* Not only BODY should be set here */
  DEBUGASSERT(meta_type & ~DF_WRITE_BODY);

  /* `meta_type` may include DF_WRITE_BODY which means the data is written
   * out to both header and body callbacks of the client.
   * Do that first (as that was the pattern before) */
  if(meta_type & DF_WRITE_BODY) {
    nwritten = do_write(data, DF_WRITE_BODY, buf, blen, &result);
    if(nwritten < 0)
      return result;
    if((size_t)nwritten < blen) {
      if(nwritten) {
        /* Some, but not all was written due to PAUSEing by callback */
        const char *remain = buf + (size_t)nwritten;
        size_t rlen = blen - (size_t)nwritten;
        result = df_out_pause(writer, data, DF_WRITE_BODY, remain, rlen);
        if(result)
          return result;
        /* buffered the BODY writeout, now buffer the complete meta
         * writeout by clearing DF_WRITE_BODY */
        meta_type &= ~DF_WRITE_BODY;
        return df_out_pause(writer, data, meta_type, buf, blen);
      }
      else {
        /* nothing was written */
        return df_out_pause(writer, data, meta_type, buf, blen);
      }
    }
    /* everything written for BODY, remove that flag so we do
     * not do it again if PAUSEing the meta write below */
    meta_type &= ~DF_WRITE_BODY;
  }

  /* BODY should no longer be set here */
  DEBUGASSERT(!(meta_type & DF_WRITE_BODY));
  nwritten = do_write(data, meta_type, buf, blen, &result);
  if(nwritten < 0)
    return result;
  if((size_t)nwritten < blen) {
    const char *remain = buf + (size_t)nwritten;
    size_t rlen = blen - (size_t)nwritten;
    return df_out_pause(writer, data, DF_WRITE_BODY, remain, rlen);
  }
  return result;
}

static CURLcode df_out_do_body(struct Curl_df_writer *writer,
                               struct Curl_easy *data,
                               const char *buf, size_t blen)
{
  CURLcode result = CURLE_OK;
  ssize_t nwritten;

  nwritten = do_write(data, DF_WRITE_BODY, buf, blen, &result);
  if(nwritten < 0)
    return result;
  if((size_t)nwritten < blen) {
    /* Not all was written due to PAUSEing by callback */
    buf += (size_t)nwritten;
    blen -= (size_t)nwritten;
    return df_out_pause(writer, data, DF_WRITE_BODY, buf, blen);
  }
  return result;
}

static void df_out_close(struct Curl_df_writer *writer,
                         struct Curl_easy *data)
{
  struct df_out_writer_ctx *ctx = (struct df_out_writer_ctx *)writer;
  size_t i;

  (void)data;
  for(i = 0; i < ctx->npaused; i++) {
    Curl_dyn_free(&ctx->paused[i].b);
  }
  ctx->npaused = 0;
}

const struct Curl_df_write_type df_writer_out = {
  "out",
  NULL,
  df_out_init,
  df_out_do_meta,
  df_out_do_body,
  df_out_close,
  sizeof(struct df_out_writer_ctx)
};

CURLcode df_out_unpause(struct Curl_df_writer *writer,
                        struct Curl_easy *data)
{
  struct df_out_writer_ctx *ctx = (struct df_out_writer_ctx *)writer;

  DEBUGASSERT(writer->dft == &df_writer_out);
  while(ctx->npaused) {
    const char *buf;
    size_t blen;
    ssize_t nwritten;
    CURLcode result;

    buf = Curl_dyn_ptr(&ctx->paused[0].b);
    blen = Curl_dyn_len(&ctx->paused[0].b);
    nwritten = do_write(data, ctx->paused[0].meta_type, buf, blen, &result);
    if(nwritten < 0) /* real error, give up */
      return result;
    else if((size_t)nwritten < blen) {
      /* partially written, PAUSED again, shrink buffer and return */
      if(nwritten > 0) {
        Curl_dyn_tail(&ctx->paused[0].b, blen - (size_t)nwritten);
      }
      return CURLE_OK;
    }
    else {
      /* completely written, shrink buffer stack */
      Curl_dyn_free(&ctx->paused[0].b);
      ctx->npaused--;
      if(ctx->npaused) {
        memmove(&ctx->paused[0], &ctx->paused[1],
                ctx->npaused * sizeof(ctx->paused[0]));
        memset(&ctx->paused[ctx->npaused], 0, sizeof(ctx->paused[0]));
      }
    }
  }
  return CURLE_OK;
}

bool df_out_is_paused(struct Curl_df_writer *writer,
                             struct Curl_easy *data)
{
  struct df_out_writer_ctx *ctx = (struct df_out_writer_ctx *)writer;
  (void)data;
  DEBUGASSERT(writer->dft == &df_writer_out);
  return (ctx->npaused > 0);
}
