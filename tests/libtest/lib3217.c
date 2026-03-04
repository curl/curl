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

#include "memdebug.h"

#include <curl/header.h>

struct header_data {
  int header_count;
  int origin_valid;
  int extended_called;
  int regular_called;
};

static size_t header_callback_extended(char *ptr, size_t size, size_t nmemb,
                                        unsigned int origin, void *userp)
{
  struct header_data *hd = (struct header_data *)userp;
  size_t len = size * nmemb;

  hd->extended_called = 1;
  hd->header_count++;

  /* Verify that origin has at least one valid bit set */
  if(origin & (CURLH_HEADER | CURLH_TRAILER | CURLH_1XX |
               CURLH_CONNECT | CURLH_PSEUDO)) {
    hd->origin_valid = 1;
  }

  /* For testing, we expect CURLH_HEADER for regular responses */
  if(origin & CURLH_HEADER) {
    (void)fwrite("HEADER: ", 1, 8, stdout);
    (void)fwrite(ptr, size, nmemb, stdout);
  }

  return len;
}

static size_t header_callback_regular(char *ptr, size_t size, size_t nmemb,
                                       void *userp)
{
  struct header_data *hd = (struct header_data *)userp;
  (void)ptr;

  /* This should NOT be called when extended callback is set */
  hd->regular_called = 1;

  return size * nmemb;
}

CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  struct header_data hd;

  memset(&hd, 0, sizeof(hd));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  /* Test 1: Extended callback receives origin parameter */
  curl_mprintf("Test 1: Extended callback with origin\n");

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED, header_callback_extended);
  easy_setopt(curl, CURLOPT_HEADERDATA, &hd);

  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(result));
    goto test_cleanup;
  }

  if(!hd.extended_called) {
    curl_mfprintf(stderr, "Extended callback was not called\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(hd.header_count == 0) {
    curl_mfprintf(stderr, "No headers received\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(!hd.origin_valid) {
    curl_mfprintf(stderr, "Origin parameter was invalid\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  curl_mprintf("Test 1 passed: Received %d headers with valid origin\n",
               hd.header_count);

  /* Test 2: Extended callback takes precedence over regular */
  curl_mprintf("\nTest 2: Extended callback precedence\n");

  /* Reset counters */
  memset(&hd, 0, sizeof(hd));

  /* Set both callbacks - extended should be used */
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback_regular);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED, header_callback_extended);
  easy_setopt(curl, CURLOPT_HEADERDATA, &hd);

  result = curl_easy_perform(curl);
  if(result) {
    curl_mfprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(result));
    goto test_cleanup;
  }

  if(hd.regular_called) {
    curl_mfprintf(stderr,
                  "Regular callback was called when extended was set\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(!hd.extended_called) {
    curl_mfprintf(stderr, "Extended callback was not called\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  curl_mprintf("Test 2 passed: Extended callback took precedence\n");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
