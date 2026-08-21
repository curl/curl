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

#include "testtrace.h"

#ifndef CURL_DISABLE_WEBSOCKETS

struct test_ws_write_err_ctx {
  CURL *easy;
  int callback_count;
  int errors;
  int closed;
};

static size_t test_ws_write_err_write_cb(char *ptr, size_t size, size_t nmemb,
                                         void *userdata)
{
  struct test_ws_write_err_ctx *ctx = userdata;
  size_t nbytes = size * nmemb;
  const struct curl_ws_frame *meta = curl_ws_meta(ctx->easy);

  (void)ptr;
  ctx->callback_count++;
  if(!meta) {
    curl_mfprintf(stderr, "write_cb: ERROR call #%d with meta=NULL\n",
                  ctx->callback_count);
    ++ctx->errors;
    return CURL_WRITEFUNC_ERROR;
  }
  if(ctx->callback_count > 2) {
    ctx->errors++;
    curl_mfprintf(stderr, "write_cb: call #%d should not happen\n",
                  ctx->callback_count);
    return 0;
  }
  if(ctx->callback_count > 1) {
    curl_mfprintf(stderr, "write_cb: call #%d return error\n",
                  ctx->callback_count);
    return 0;
  }
  return nbytes;
}
#endif /* CURL_DISABLE_WEBSOCKETS */

static CURLcode test_cli_ws_write_err(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  struct test_ws_write_err_ctx ctx;
  CURLM *multi;
  int still_running = 0;
  int msgs_left = 0;
  int done = 0;

  memset(&ctx, 0, sizeof(ctx));
  setbuf(stdout, NULL);

  curl_global_init(CURL_GLOBAL_ALL);

  ctx.easy = curl_easy_init();
  multi = curl_multi_init();
  if(!ctx.easy || !multi) {
    curl_mfprintf(stderr, "main: ERROR creating easy/multi\n");
    ctx.errors = 1;
    goto out;
  }

  curl_easy_setopt(ctx.easy, CURLOPT_URL, URL);
  curl_easy_setopt(ctx.easy, CURLOPT_WRITEFUNCTION,
                   test_ws_write_err_write_cb);
  curl_easy_setopt(ctx.easy, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(ctx.easy, CURLOPT_VERBOSE, 1L);

  curl_multi_add_handle(multi, ctx.easy);
  curl_multi_perform(multi, &still_running);

  while(still_running && !ctx.closed && !ctx.errors) {

    curl_mfprintf(stderr, "main: poll\n");
    curl_multi_poll(multi, NULL, 0, 100, NULL);
    curl_mfprintf(stderr, "main: perform\n");
    curl_multi_perform(multi, &still_running);

    while(!done) {
      CURLMsg *msg = curl_multi_info_read(multi, &msgs_left);
      if(!msg)
        break;
      if(msg->msg == CURLMSG_DONE) {
        curl_mfprintf(stderr, "main: done result=%d (%s)\n",
                      (int)msg->data.result,
                      curl_easy_strerror(msg->data.result));
        done = 1;
      }
    }
  }

out:
  if(ctx.easy) {
    if(multi)
      curl_multi_remove_handle(multi, ctx.easy);
    curl_easy_cleanup(ctx.easy);
  }
  if(multi)
    curl_multi_cleanup(multi);
  curl_global_cleanup();

  return (ctx.errors || (ctx.callback_count != 2)) ?
         CURLE_WRITE_ERROR : CURLE_OK;

#else /* !CURL_DISABLE_WEBSOCKETS */
  (void)URL;
  curl_mfprintf(stderr, "WebSockets not enabled in libcurl\n");
  return (CURLcode)1;
#endif /* CURL_DISABLE_WEBSOCKETS */
}
