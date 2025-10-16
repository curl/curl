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

#include "memdebug.h"

#ifdef USE_THREADS_POSIX
#include <pthread.h>
#endif

#include "curl_threads.h"

#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)

static size_t t3036_header_callback(char *ptr, size_t size, size_t nmemb,
                                    void *userp)
{
  size_t len = size * nmemb;
  (void)userp;
  (void)fwrite(ptr, size, nmemb, stdout);
  return len;
}

struct t3036_ctx {
  CURL *easy;
  CURLcode result;
};

static CURL_THREAD_RETURN_T CURL_STDCALL t3036_thread(void *ptr)
{
  struct t3036_ctx *ctx = ptr;

  while(!ctx->result) {
    ctx->result = curl_easy_setopt(ctx->easy, CURLOPT_VERBOSE, 1L);
  }
  return 0;
}

static CURLcode test_lib3036(const char *URL)
{
  CURLcode res = CURLE_OK;
  curl_thread_t thread = curl_thread_t_null;
  CURL *easy;
  struct t3036_ctx ctx;

  memset(&ctx, 0, sizeof(ctx));
  curl_global_init(CURL_GLOBAL_ALL);

  easy = curl_easy_init();
  if(!easy) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  ctx.easy = easy;
  ctx.result = CURLE_OK;
  thread = Curl_thread_create(t3036_thread, (void *)&ctx);

  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_HEADERFUNCTION, t3036_header_callback);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
  /* Perform the request, res will get the return code */
  res = curl_easy_perform(easy);

  /* Check for errors */
  if(res != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
  }

test_cleanup:
  if(thread != curl_thread_t_null) {
    Curl_thread_join(&thread);
    if(!res)
      res = ctx.result;
  }
  if(easy)
    curl_easy_cleanup(easy);
  curl_global_cleanup();
  return res;
}

#else /* no thread support */

static CURLcode test_lib3036(const char *URL)
{
  (void)URL;
  return CURLE_NOT_BUILT_IN;
}

#endif /* USE_THREADS_POSIX) || USE_THREADS_WIN32 */
