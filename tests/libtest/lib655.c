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

static const char *TEST_DATA_STRING = "Test data";
static int cb_count = 0;

static int resolver_alloc_cb_fail(void *resolver_state, void *reserved,
                                  void *userdata)
{
  (void)resolver_state;
  (void)reserved;

  cb_count++;
  if(strcmp(userdata, TEST_DATA_STRING)) {
    curl_mfprintf(stderr, "Invalid test data received");
    exit(1);
  }

  return 1;
}

static int resolver_alloc_cb_pass(void *resolver_state, void *reserved,
                                  void *userdata)
{
  (void)resolver_state;
  (void)reserved;

  cb_count++;
  if(strcmp(userdata, TEST_DATA_STRING)) {
    curl_mfprintf(stderr, "Invalid test data received");
    exit(1);
  }

  return 0;
}

static CURLcode test_lib655(const char *URL)
{
  CURL *curl;
  CURLcode result = CURLE_OK;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Set the URL that is about to receive our first request. */
  test_setopt(curl, CURLOPT_URL, URL);

  test_setopt(curl, CURLOPT_RESOLVER_START_DATA, TEST_DATA_STRING);
  test_setopt(curl, CURLOPT_RESOLVER_START_FUNCTION, resolver_alloc_cb_fail);

  /* this should fail */
  result = curl_easy_perform(curl);
  if(result != CURLE_ABORTED_BY_CALLBACK) {
    curl_mfprintf(stderr, "curl_easy_perform should have returned "
                  "CURLE_ABORTED_BY_CALLBACK but instead returned error %d\n",
                  result);
    if(result == CURLE_OK)
      result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* Set the URL that receives our second request. */
  test_setopt(curl, CURLOPT_URL, libtest_arg2);

  test_setopt(curl, CURLOPT_RESOLVER_START_FUNCTION, resolver_alloc_cb_pass);

  /* this should succeed */
  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "curl_easy_perform failed.\n");
    goto test_cleanup;
  }

  if(cb_count != 2) {
    curl_mfprintf(stderr, "Unexpected number of callbacks: %d\n", cb_count);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
