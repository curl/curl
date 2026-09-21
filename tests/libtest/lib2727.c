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

#define T2727_NUM_REQUESTS 3

static int t2727_run_multi_loop(CURLM *multi)
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
#endif /* CURL_DISABLE_WEBSOCKETS */

static CURLcode test_lib2727(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  /* Repeatedly request a WebSocket upgrade over a single easy handle that is
   * re-added to the same multi handle for each request, with
   * CURLOPT_CONNECT_ONLY set to 2 (the WebSocket flavour) as an application
   * that intends to take the socket over must do.
   *
   * Every request is refused (the server answers 200, not 101), so every
   * request must return CURLE_WS_DENIED and leave an ordinary, complete
   * HTTP/1.1 response on a connection that is still usable.
   *
   * The point of the test is that requests 2..N must REUSE the connection
   * left behind by request 1 rather than opening a new one. Two things have
   * to hold for that to happen:
   *
   *   - conn->bits.connect_only, latched from CURLOPT_CONNECT_ONLY when the
   *     connection was created, must be cleared when the upgrade is refused.
   *     Otherwise url_match_connect_config() refuses to match the connection.
   *
   *   - a ws:// request must be allowed to match the pooled connection even
   *     though the refused upgrade rewrote that connection's scheme to http.
   *
   * This is the pattern a connection-pooling application produces, and it is
   * not covered by test2724 (no CONNECT_ONLY, and its second request is a
   * plain http:// one). */
  CURL *easy = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  CURLMsg *msg;
  int msgs_in_queue;
  char target_url[256];
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;
  int i;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);

  multi_init(multi);
  easy_init(easy);

  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  for(i = 1; i <= T2727_NUM_REQUESTS; i++) {
    long response_code = 0;

    curl_msnprintf(target_url, sizeof(target_url), "ws://%s:%s/path/ws/2727",
                   address, port);
    easy_setopt(easy, CURLOPT_URL, target_url);

    /* The application intends to take the socket over after a successful
     * upgrade. 2 selects the WebSocket flavour of connect-only. */
    easy_setopt(easy, CURLOPT_CONNECT_ONLY, 2L);

    multi_add_handle(multi, easy);

    if(t2727_run_multi_loop(multi)) {
      result = TEST_ERR_MULTI;
      goto test_cleanup;
    }

    msg = curl_multi_info_read(multi, &msgs_in_queue);
    if(!msg || msg->easy_handle != easy || msg->msg != CURLMSG_DONE) {
      curl_mfprintf(stderr, "TEST FAILURE: Request %d did not complete or "
                    "multi_info_read failed.\n", i);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    if(msg->data.result != CURLE_WS_DENIED) {
      curl_mfprintf(stderr, "TEST FAILURE: Request %d returned CURLcode %d "
                    "(%s), expected CURLE_WS_DENIED (%d).\n", i,
                    (int)msg->data.result,
                    curl_easy_strerror(msg->data.result),
                    (int)CURLE_WS_DENIED);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response_code);

    curl_mfprintf(stderr, "Request %d (WS refused) completed. "
                  "CURLcode: %d (%s). HTTP Code: %ld.\n", i,
                  (int)msg->data.result,
                  curl_easy_strerror(msg->data.result), response_code);

    if(response_code != 200) {
      curl_mfprintf(stderr, "TEST FAILURE: Request %d returned %ld, "
                    "expected 200.\n", i, response_code);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    /* The upgrade was refused, so the application never took the socket
     * over. Drop connect-only again so that curl_multi_remove_handle() does
     * not close the connection on us. */
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
