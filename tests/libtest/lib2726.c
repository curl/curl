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

static int t2726_run_multi_loop(CURLM *multi)
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

static CURLcode test_lib2726(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  /* Test that a WebSocket upgrade refused with a 3xx redirect response still
   * returns CURLE_WS_DENIED and that the redirect is NOT followed, even when
   * CURLOPT_FOLLOWLOCATION is enabled.  The test definition verifies that only
   * the single WebSocket upgrade request is sent (no follow-up request to the
   * Location target). */
  CURL *curl_ws_refused = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  long response_code = 0;
  CURLMsg *msg;
  int msgs_in_queue;
  char target_url[256];
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  /* Setup WebSocket upgrade refused with a 3xx redirect */

  easy_init(curl_ws_refused);

  curl_msnprintf(target_url, sizeof(target_url), "ws://%s:%s/path/ws/2726",
                 address, port);
  easy_setopt(curl_ws_refused, CURLOPT_URL, target_url);
  easy_setopt(curl_ws_refused, CURLOPT_VERBOSE, 1L);
  /* Follow redirects: a refused upgrade must still not follow the 3xx. */
  easy_setopt(curl_ws_refused, CURLOPT_FOLLOWLOCATION, 1L);

  multi_add_handle(multi, curl_ws_refused);

  if(t2726_run_multi_loop(multi)) {
    result = TEST_ERR_MULTI;
    goto test_cleanup;
  }

  msg = curl_multi_info_read(multi, &msgs_in_queue);
  if(msg && msg->easy_handle == curl_ws_refused
     && msg->msg == CURLMSG_DONE) {

    /* Verify CURLE_WS_DENIED was returned and that the redirect response code
     * is reported, i.e. the 3xx was not followed. */
    if(msg->data.result != CURLE_WS_DENIED) {
      curl_mfprintf(stderr, "TEST FAILURE: Request 1 returned CURLcode %d "
                    "(%s), expected CURLE_WS_DENIED (%d).\n",
                    (int)msg->data.result,
                    curl_easy_strerror(msg->data.result),
                    (int)CURLE_WS_DENIED);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    curl_easy_getinfo(curl_ws_refused, CURLINFO_RESPONSE_CODE, &response_code);

    curl_mfprintf(stderr, "Request 1 (WS refused + redirect) completed. "
                  "CURLcode: %d (%s). HTTP Code: %ld.\n",
                  (int)msg->data.result,
                  curl_easy_strerror(msg->data.result),
                  response_code);

    if(response_code != 302) {
      curl_mfprintf(stderr, "TEST FAILURE: Request 1 returned HTTP %ld, "
                    "expected 302 (redirect not followed).\n", response_code);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
  }
  else {
    curl_mfprintf(stderr, "TEST FAILURE: Request 1 did not complete or "
                  "multi_info_read failed.\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  if(curl_ws_refused)
    curl_multi_remove_handle(multi, curl_ws_refused);
  if(curl_ws_refused)
    curl_easy_cleanup(curl_ws_refused);
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
