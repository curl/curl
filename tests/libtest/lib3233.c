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

struct test3233_ctx {
  CURL *pushed;
  int transfers;
  int pushes;
};

static int push_callback(CURL *parent, CURL *easy, size_t num_headers,
                         struct curl_pushheaders *headers, void *userp)
{
  struct test3233_ctx *ctx = userp;

  (void)parent;
  (void)num_headers;
  (void)headers;

  ctx->pushed = easy;
  ctx->transfers++;
  ctx->pushes++;
  return CURL_PUSH_OK;
}

static CURLcode test_lib3233(const char *URL)
{
  struct test3233_ctx ctx = { NULL, 1, 0 };
  struct curl_slist *connect_to = NULL;
  CURLM *multi = NULL;
  CURL *easy = NULL;
  CURLcode result = CURLE_OK;
  CURLMcode mresult;

  if(!URL || !libtest_arg2)
    return TEST_ERR_MAJOR_BAD;

  global_init(CURL_GLOBAL_ALL);

  easy_init(easy);
  multi_init(multi);

  connect_to = curl_slist_append(NULL, libtest_arg2);
  if(!connect_to) {
    result = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_CONNECT_TO, connect_to);
  easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  multi_setopt(multi, CURLMOPT_PUSHFUNCTION, push_callback);
  multi_setopt(multi, CURLMOPT_PUSHDATA, &ctx);
  multi_add_handle(multi, easy);

  while(ctx.transfers) {
    struct CURLMsg *msg;
    int msgs_left;
    int running;

    mresult = curl_multi_perform(multi, &running);
    if(mresult != CURLM_OK) {
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    /* !checksrc! disable EQUALSNULL 1 */
    while((msg = curl_multi_info_read(multi, &msgs_left)) != NULL) {
      if(msg->msg == CURLMSG_DONE) {
        CURL *done = msg->easy_handle;

        ctx.transfers--;
        curl_multi_remove_handle(multi, done);
        curl_easy_cleanup(done);
        if(done == easy)
          easy = NULL;
        if(done == ctx.pushed)
          ctx.pushed = NULL;
      }
    }

    if(ctx.transfers) {
      mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);
      if(mresult != CURLM_OK) {
        result = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
    }
  }

  if(ctx.pushes != 1)
    result = TEST_ERR_FAILURE;

test_cleanup:
  if(ctx.pushed) {
    if(multi)
      curl_multi_remove_handle(multi, ctx.pushed);
    curl_easy_cleanup(ctx.pushed);
  }
  if(easy) {
    if(multi)
      curl_multi_remove_handle(multi, easy);
    curl_easy_cleanup(easy);
  }
  if(multi)
    curl_multi_cleanup(multi);
  curl_slist_free_all(connect_to);
  curl_global_cleanup();
  return result;
}
