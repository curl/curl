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

static CURLcode expect_xfers_done(CURLM *multi, curl_off_t expected)
{
  curl_off_t value = -1;
  CURLMcode mresult = curl_multi_get_offt(multi, CURLMINFO_XFERS_DONE,
                                          &value);

  if(mresult != CURLM_OK) {
    curl_mfprintf(stderr, "curl_multi_get_offt() failed with code %d\n",
                  (int)mresult);
    return TEST_ERR_MULTI;
  }
  if(value != expected) {
    curl_mfprintf(stderr,
                  "Expected %" CURL_FORMAT_CURL_OFF_T
                  " unread completion messages, got %"
                  CURL_FORMAT_CURL_OFF_T "\n",
                  expected, value);
    return TEST_ERR_FAILURE;
  }
  return CURLE_OK;
}

static CURLcode test_lib2453(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  CURLMsg *msg;
  int msgs_left;
  int still_running;

  start_test_timing();
  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);
  easy_init(curl);

  result = expect_xfers_done(multi, 0);
  if(result)
    goto test_cleanup;

  easy_setopt(curl, CURLOPT_URL, URL);
  multi_add_handle(multi, curl);

  do {
    CURLMcode mresult;
    int numfds;

    multi_perform(multi, &still_running);
    if(!still_running)
      break;

    mresult = curl_multi_poll(multi, NULL, 0, TEST_HANG_TIMEOUT, &numfds);
    if(mresult != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_poll() failed with code %d\n",
                    (int)mresult);
      result = TEST_ERR_MULTI;
      goto test_cleanup;
    }
    abort_on_test_timeout();
  } while(still_running);

  result = expect_xfers_done(multi, 1);
  if(result)
    goto test_cleanup;

  msg = curl_multi_info_read(multi, &msgs_left);
  if(!msg || msg->msg != CURLMSG_DONE || msg->easy_handle != curl ||
     msg->data.result != CURLE_OK || msgs_left) {
    curl_mfprintf(stderr, "Unexpected completion message\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  result = expect_xfers_done(multi, 0);
  if(result)
    goto test_cleanup;

  multi_remove_handle(multi, curl);
  multi_perform(multi, &still_running);
  if(still_running) {
    curl_mfprintf(stderr, "Completed transfer still counted as running\n");
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  if(multi && curl)
    curl_multi_remove_handle(multi, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return result;
}
