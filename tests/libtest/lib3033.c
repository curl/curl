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
#include "test.h"

#include "testutil.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 1000

static int debug_func(CURL *handle, curl_infotype type, char *data,
               size_t size, void *userptr)
{
  (void)handle;
  (void)size;
  (void)userptr;
  if(type == CURLINFO_TEXT)
    curl_mfprintf(stderr, "debug_func[%d]: %s", type, data);
  return 0;
}

static CURLcode req_test(CURLM *multi, CURL *easy, char *url_3033, int index)
{
  CURLMsg *msg = NULL;
  CURLcode res = CURLE_OK;
  int still_running = 0;

  curl_easy_reset(easy);
  curl_easy_setopt(easy, CURLOPT_URL, url_3033);
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, debug_func);
  if(index == 0) {
    curl_mprintf("not set CURLOPT_FRESH_CONNECT for req #0\n");
  }
  else if(index == 1) {
    curl_easy_setopt(easy, CURLOPT_FRESH_CONNECT, 2L);
    curl_mprintf("set CURLOPT_FRESH_CONNECT=2 for req #1\n");
    curl_easy_setopt(easy, CURLOPT_FORBID_REUSE, 1L);
    curl_mprintf("set CURLOPT_FORBID_REUSE=1 for req #1\n");
  }
  else if(index == 2) {
    curl_mprintf("not set CURLOPT_FRESH_CONNECT for req #2\n");
  }
  curl_multi_add_handle(multi, easy);

  do {
    CURLMcode mres;
    int num;
    curl_multi_perform(multi, &still_running);
    mres = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);
    if(mres != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto stale_test_cleanup;
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
        goto stale_test_cleanup;
      }

      curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &num_connects);
      if(index == 1 && num_connects == 0) {
        curl_mfprintf(stderr, "req 1 should not reuse connection in pool\n");
        res = TEST_ERR_MAJOR_BAD;
        goto stale_test_cleanup;
      }
      else if(index == 2 && num_connects == 0) {
        curl_mfprintf(stderr, "req 2 should not reuse connection in pool\n");
        res = TEST_ERR_MAJOR_BAD;
        goto stale_test_cleanup;
      }
    }
  } while(msg);

stale_test_cleanup:

  curl_multi_remove_handle(multi, easy);

  return res;
}

CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);
  easy_init(curl);

  res = req_test(multi, curl, URL, 0);
  if(res != CURLE_OK)
    goto test_cleanup;
  res = req_test(multi, curl, URL, 1);
  if(res != CURLE_OK)
    goto test_cleanup;
  res = req_test(multi, curl, URL, 2);
  if(res != CURLE_OK)
    goto test_cleanup;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return res; /* return the final return code */
}
