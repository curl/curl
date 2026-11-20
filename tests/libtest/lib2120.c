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

struct t2120_ctx {
  CURL *easy;
  size_t received;
  int paused;
  int pauses;
};

static size_t t2120_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct t2120_ctx *ctx = userdata;
  size_t len = size * nmemb;
  size_t i;
  static const char expected[] = "firstsecondthird";
  if(ctx->paused) {
    curl_mfprintf(stderr, "write callback invoked while paused\n");
    return CURL_WRITEFUNC_ERROR;
  }
  for(i = 0; i < len; i++) {
    if(testnum == 2121 ? ptr[i] != 'A' :
       ctx->received + i >= sizeof(expected) - 1 ||
       ptr[i] != expected[ctx->received + i])
      return CURL_WRITEFUNC_ERROR;
  }
  ctx->received += len;
  if(!ctx->pauses) {
    ctx->paused = 1;
    ctx->pauses++;
    if(curl_easy_pause(ctx->easy, CURLPAUSE_RECV))
      return CURL_WRITEFUNC_ERROR;
  }
  return len;
}

static CURLcode test_lib2120(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLMsg *msg;
  CURLcode result = CURLE_OK;
  struct t2120_ctx ctx;
  int running = 0;
  int pending;

  memset(&ctx, 0, sizeof(ctx));
  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);
  multi_init(multi);
  ctx.easy = curl;
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t2120_write);
  easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
  easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
  if(testnum == 2121)
    easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
  multi_add_handle(multi, curl);
  do {
    multi_perform(multi, &running);
    if(ctx.paused) {
      if(!running) {
        result = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      ctx.paused = 0;
      result = curl_easy_pause(curl, CURLPAUSE_CONT);
      if(result)
        goto test_cleanup;
    }
    if(running) {
      CURLMcode mc = curl_multi_poll(multi, NULL, 0, 10, NULL);
      if(mc) {
        result = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
    }
  } while(running);

  msg = curl_multi_info_read(multi, &pending);
  if(!msg || msg->msg != CURLMSG_DONE)
    result = TEST_ERR_MAJOR_BAD;
  else
    result = msg->data.result;
  if(!result)
    curl_mprintf("Received %zu bytes, paused %d time\n",
                 ctx.received, ctx.pauses);

test_cleanup:
  if(multi && curl)
    curl_multi_remove_handle(multi, curl);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
