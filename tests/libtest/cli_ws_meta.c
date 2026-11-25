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
#include "first.h"

#ifndef CURL_DISABLE_WEBSOCKETS

#define WS_META_FRAME_SIZE 200000
#define WS_META_RECV_SIZE 262144L

struct test_ws_meta_ctx {
  CURL *easy;
  size_t received;
  size_t callbacks;
  size_t payload_callbacks;
  bool close_seen;
};

static size_t test_ws_meta_fail(struct test_ws_meta_ctx *ctx,
                                const char *reason, size_t nbytes,
                                const struct curl_ws_frame *meta)
{
  curl_mfprintf(stderr, "callback #%zu: %s (bytes=%zu, flags=0x%x, "
                "len=%zu, offset=%" FMT_OFF_T ", bytesleft=%" FMT_OFF_T
                ")\n", ctx->callbacks, reason, nbytes,
                (unsigned int)meta->flags, meta->len,
                meta->offset, meta->bytesleft);
  return CURL_WRITEFUNC_ERROR;
}

static size_t test_ws_meta_write_cb(char *ptr, size_t size, size_t nmemb,
                                    void *userdata)
{
  struct test_ws_meta_ctx *ctx = userdata;
  const struct curl_ws_frame *meta = curl_ws_meta(ctx->easy);
  size_t nbytes = size * nmemb;
  size_t i;

  ++ctx->callbacks;
  if(!meta) {
    curl_mfprintf(stderr, "callback #%zu: curl_ws_meta() returned NULL\n",
                  ctx->callbacks);
    return CURL_WRITEFUNC_ERROR;
  }

  if(meta->flags & CURLWS_CLOSE) {
    if(ctx->close_seen || ctx->received != WS_META_FRAME_SIZE) {
      return test_ws_meta_fail(ctx, "unexpected or premature CLOSE",
                               nbytes, meta);
    }
    ctx->close_seen = TRUE;
    return nbytes;
  }

  if(ctx->close_seen ||
     (meta->flags & (CURLWS_TEXT | CURLWS_BINARY)) != CURLWS_BINARY ||
     (meta->flags & CURLWS_CONT)) {
    return test_ws_meta_fail(ctx, "unexpected frame type or continuation",
                             nbytes, meta);
  }
  if(meta->len != nbytes) {
    return test_ws_meta_fail(ctx, "metadata length differs from callback",
                             nbytes, meta);
  }
  if(ctx->received > WS_META_FRAME_SIZE ||
     nbytes > WS_META_FRAME_SIZE - ctx->received) {
    return test_ws_meta_fail(ctx, "received more than the expected frame",
                             nbytes, meta);
  }
  if(meta->offset != (curl_off_t)ctx->received) {
    return test_ws_meta_fail(ctx, "metadata offset is not cumulative",
                             nbytes, meta);
  }
  if(meta->bytesleft !=
     (curl_off_t)(WS_META_FRAME_SIZE - ctx->received - nbytes)) {
    return test_ws_meta_fail(ctx, "metadata bytesleft is incorrect",
                             nbytes, meta);
  }
  if(meta->offset + (curl_off_t)meta->len + meta->bytesleft !=
     (curl_off_t)WS_META_FRAME_SIZE) {
    return test_ws_meta_fail(ctx, "metadata does not describe the full frame",
                             nbytes, meta);
  }

  for(i = 0; i < nbytes; ++i) {
    unsigned char expected =
      (unsigned char)((ctx->received + i) % 251);
    if((unsigned char)ptr[i] != expected) {
      return test_ws_meta_fail(ctx, "payload byte is incorrect",
                               nbytes, meta);
    }
  }

  ctx->received += nbytes;
  ++ctx->payload_callbacks;
  return nbytes;
}

#endif /* CURL_DISABLE_WEBSOCKETS */

static CURLcode test_cli_ws_meta(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  struct test_ws_meta_ctx ctx;
  CURLcode result;

  if((size_t)CURL_MAX_WRITE_SIZE >= (size_t)WS_META_RECV_SIZE) {
    curl_mfprintf(stderr, "receive buffer must exceed CURL_MAX_WRITE_SIZE\n");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  memset(&ctx, 0, sizeof(ctx));
  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return CURLE_FAILED_INIT;
  }

  ctx.easy = curl_easy_init();
  if(!ctx.easy) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = curl_easy_setopt(ctx.easy, CURLOPT_URL, URL);
  if(!result)
    result = curl_easy_setopt(ctx.easy, CURLOPT_BUFFERSIZE,
                              WS_META_RECV_SIZE);
  if(!result)
    result = curl_easy_setopt(ctx.easy, CURLOPT_WRITEFUNCTION,
                              test_ws_meta_write_cb);
  if(!result)
    result = curl_easy_setopt(ctx.easy, CURLOPT_WRITEDATA, &ctx);
  if(!result)
    result = curl_easy_perform(ctx.easy);
  if(!result && (ctx.received != WS_META_FRAME_SIZE ||
                 ctx.payload_callbacks < 2 || !ctx.close_seen)) {
    curl_mfprintf(stderr, "incomplete WebSocket response: received %zu of "
                  "%u bytes in %zu payload callbacks, CLOSE %s\n",
                  ctx.received,
                  (unsigned int)WS_META_FRAME_SIZE,
                  ctx.payload_callbacks,
                  ctx.close_seen ? "received" : "not received");
    result = CURLE_PARTIAL_FILE;
  }
  if(!result) {
    curl_mfprintf(stderr, "verified %zu BINARY callbacks and %zu payload "
                  "bytes, CLOSE received\n", ctx.payload_callbacks,
                  ctx.received);
  }

out:
  if(ctx.easy)
    curl_easy_cleanup(ctx.easy);
  curl_global_cleanup();
  return result;

#else /* CURL_DISABLE_WEBSOCKETS */
  (void)URL;
  curl_mfprintf(stderr, "WebSockets not enabled in libcurl\n");
  return (CURLcode)1;
#endif /* CURL_DISABLE_WEBSOCKETS */
}
