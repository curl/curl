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

struct t2724_step {
  const char *scheme;       /* URL scheme to request */
  const char *path;         /* path component, to tell the requests apart */
  long connect_only;        /* CURLOPT_CONNECT_ONLY for this request */
  CURLcode expect_result;   /* expected transfer result */
  long expect_code;         /* expected CURLINFO_RESPONSE_CODE */
  const char *what;         /* description, ends up in the stderr log */
};

/* The server answers every request with 200, so each WebSocket upgrade is
 * refused. Request 1 creates the connection, requests 2 and 3 must reuse it,
 * once as http: and once as ws:. */
static const struct t2724_step t2724_steps[] = {
  { "ws",   "ws",   2L, CURLE_WS_DENIED, 200L, "WS refused, CONNECT_ONLY=2" },
  { "http", "http", 0L, CURLE_OK,        200L, "plain HTTP, reused conn" },
  { "ws",   "ws",   2L, CURLE_WS_DENIED, 200L, "WS refused, reused conn" }
};

static int t2724_run_multi_loop(CURLM *multi)
{
  int still_running = 0;
  CURLMcode mresult;

  do {
    mresult = curl_multi_perform(multi, &still_running);
    if(mresult != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_perform failed: %s\n",
                    curl_multi_strerror(mresult));
      return 1;
    }

    if(still_running) {
      mresult = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, NULL);
      if(mresult != CURLM_OK) {
        curl_mfprintf(stderr, "curl_multi_wait failed: %s\n",
                      curl_multi_strerror(mresult));
        return 1;
      }
    }
  } while(still_running);

  return 0;
}

/* Drive `multi` until done and check how the transfer on `easy` ended. */
static CURLcode t2724_check(CURLM *multi, CURL *easy, int num,
                            const struct t2724_step *step)
{
  CURLMsg *msg;
  int msgs_in_queue;
  long response_code = 0;

  if(t2724_run_multi_loop(multi))
    return TEST_ERR_MULTI;

  msg = curl_multi_info_read(multi, &msgs_in_queue);
  if(!msg || msg->easy_handle != easy || msg->msg != CURLMSG_DONE) {
    curl_mfprintf(stderr, "TEST FAILURE: Request %d did not complete or "
                  "multi_info_read failed.\n", num);
    return TEST_ERR_FAILURE;
  }

  if(msg->data.result != step->expect_result) {
    curl_mfprintf(stderr, "TEST FAILURE: Request %d returned CURLcode %d "
                  "(%s), expected %d.\n", num, (int)msg->data.result,
                  curl_easy_strerror(msg->data.result),
                  (int)step->expect_result);
    return TEST_ERR_FAILURE;
  }

  curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);

  curl_mfprintf(stderr, "Request %d (%s) completed. CURLcode: %d (%s). "
                "HTTP Code: %ld.\n", num, step->what, (int)msg->data.result,
                curl_easy_strerror(msg->data.result), response_code);

  if(response_code != step->expect_code) {
    curl_mfprintf(stderr, "TEST FAILURE: Request %d returned HTTP %ld, "
                  "expected %ld.\n", num, response_code, step->expect_code);
    return TEST_ERR_FAILURE;
  }

  return CURLE_OK;
}
#endif /* CURL_DISABLE_WEBSOCKETS */

static CURLcode test_lib2724(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  /* A refused WebSocket upgrade must report CURLE_WS_DENIED with the HTTP
   * response code still available, and must leave behind an ordinary, usable
   * HTTP/1.1 connection rather than closing it.
   *
   * One easy handle is re-added to the same multi handle for each request,
   * which is the pattern a connection-pooling application produces. Every
   * request goes to a server that answers 200 instead of 101, so every
   * upgrade is refused.
   *
   * Request 1 sets CURLOPT_CONNECT_ONLY to 2 (the WebSocket flavour) as an
   * application that intends to take the socket over must do, so the
   * connection is created with conn->bits.connect_only latched on.
   *
   * Requests 2 and 3 must then REUSE that connection rather than open a new
   * one, which requires three things to hold:
   *
   *   - conn->bits.connect_only must be cleared when the upgrade is refused.
   *     Otherwise url_match_connect_config() refuses to match the connection.
   *
   *   - the refused upgrade must rewrite the connection's scheme to http, so
   *     that the plain http:// request 2 matches it.
   *
   *   - a ws:// request must be allowed to match that pooled http connection,
   *     so that request 3 matches it again.
   */
  CURL *easy = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  char target_url[256];
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;
  size_t i;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);

  multi_init(multi);
  easy_init(easy);

  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  for(i = 0; i < CURL_ARRAYSIZE(t2724_steps); i++) {
    const struct t2724_step *step = &t2724_steps[i];

    curl_msnprintf(target_url, sizeof(target_url), "%s://%s:%s/path/%s/2724",
                   step->scheme, address, port, step->path);
    easy_setopt(easy, CURLOPT_URL, target_url);
    easy_setopt(easy, CURLOPT_CONNECT_ONLY, step->connect_only);

    multi_add_handle(multi, easy);

    result = t2724_check(multi, easy, (int)i + 1, step);
    if(result)
      goto test_cleanup;

    /* No upgrade succeeded, so the application never took a socket over.
     * Drop connect-only again so that curl_multi_remove_handle() does not
     * close the connection on us. */
    easy_setopt(easy, CURLOPT_CONNECT_ONLY, 0L);
    multi_remove_handle(multi, easy);
  }

test_cleanup:
  if(easy) {
    curl_multi_remove_handle(multi, easy);
    curl_easy_cleanup(easy);
  }
  if(multi)
    curl_multi_cleanup(multi);
  curl_global_cleanup();

  return result;
#else
  (void)URL;
  curl_mfprintf(stderr, "Missing support\n");
  return CURLE_UNSUPPORTED_PROTOCOL;
#endif
}
