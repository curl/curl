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

struct t2725_step {
  CURLcode expect_result;   /* expected transfer result */
  long expect_code;         /* expected CURLINFO_RESPONSE_CODE */
  const char *what;         /* description, ends up in the stderr log */
};

/* The server answers the first request with a 302 and the second, via
 * "swsbounce", with a 200 carrying "Connection: close". */
static const struct t2725_step t2725_steps[] = {
  { CURLE_WS_DENIED, 302L, "WS refused + redirect" },
  { CURLE_WS_DENIED, 200L, "WS refused + conn close" }
};

static int t2725_run_multi_loop(CURLM *multi)
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
static CURLcode t2725_check(CURLM *multi, CURL *easy, int num,
                            const struct t2725_step *step)
{
  CURLMsg *msg;
  int msgs_in_queue;
  long response_code = 0;

  if(t2725_run_multi_loop(multi))
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

static CURLcode test_lib2725(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  /* A refused WebSocket upgrade is terminal for the transfer: the response is
   * reported as CURLE_WS_DENIED and none of the follow-up handling an
   * ordinary HTTP response would get is applied. Two responses are checked:
   *
   * Request 1: a 3xx with a Location header, with CURLOPT_FOLLOWLOCATION
   * enabled. The redirect must NOT be followed and CURLINFO_RESPONSE_CODE
   * must report the 302. The test definition verifies that no request to the
   * Location target is sent.
   *
   * Request 2: a 200 with "Connection: close". The upgrade is refused the
   * same way, but the close must still be honored. The connection is shut
   * down rather than returned to the cache, even though a refused upgrade
   * normally keeps the connection alive (see test 2724).
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

  curl_msnprintf(target_url, sizeof(target_url), "ws://%s:%s/path/ws/2725",
                 address, port);
  easy_setopt(easy, CURLOPT_URL, target_url);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  /* A refused upgrade must not follow the 3xx of request 1. Request 2 gets a
   * 200 without a Location, so this stays a no-op there. */
  easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);

  for(i = 0; i < CURL_ARRAYSIZE(t2725_steps); i++) {
    multi_add_handle(multi, easy);

    result = t2725_check(multi, easy, (int)i + 1, &t2725_steps[i]);
    if(result)
      goto test_cleanup;

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
