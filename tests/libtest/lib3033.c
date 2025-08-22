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

#include "memdebug.h"

static CURLcode t3033_req_test(CURLM *multi, CURL *easy,
                               const char *URL, int index)
{
  CURLMsg *msg = NULL;
  CURLcode res = CURLE_OK;
  int still_running = 0;

  if(index == 1) {
    curl_multi_setopt(multi, CURLMOPT_NETWORK_CHANGED,
                      CURLMNWC_CLEAR_CONNS);
    curl_mprintf("[1] signal network change\n");
  }
  else {
    curl_mprintf("[%d] no network change\n", index);
  }

  curl_easy_reset(easy);
  curl_easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(easy, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  curl_multi_add_handle(multi, easy);

  do {
    CURLMcode mres;
    int num;
    curl_multi_perform(multi, &still_running);
    mres = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);
    if(mres != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
  } while(still_running);

  do {
    long num_connects = 0L;
    msg = curl_multi_info_read(multi, &still_running);
    if(msg) {
      if(msg->msg != CURLMSG_DONE)
        continue;

      res = msg->data.result;
      if(res != CURLE_OK) {
        curl_mfprintf(stderr, "curl_multi_info_read() returned %d\n", res);
        goto test_cleanup;
      }

      curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &num_connects);
      if(index == 1 && num_connects == 0) {
        curl_mprintf("[1] should not reuse connection in pool\n");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      else if(index == 2 && num_connects) {
        curl_mprintf("[2] should have reused connection from [1]\n");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
    }
  } while(msg);

test_cleanup:

  curl_multi_remove_handle(multi, easy);

  return res;
}

static CURLcode test_lib3033(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);
  easy_init(curl);

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;

  res = t3033_req_test(multi, curl, URL, 0);
  if(res != CURLE_OK)
    goto test_cleanup;
  res = t3033_req_test(multi, curl, URL, 1);
  if(res != CURLE_OK)
    goto test_cleanup;
  res = t3033_req_test(multi, curl, URL, 2);
  if(res != CURLE_OK)
    goto test_cleanup;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return res; /* return the final return code */
}
