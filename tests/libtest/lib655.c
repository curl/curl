/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

const char TEST_DATA_STRING[] = "Test data";
static int cb_count = 0;
static int
resolver_alloc_cb_fail (void *resolver_data, void *user_data)
{
  cb_count++;
  if(strcmp(user_data, TEST_DATA_STRING)) {
    fprintf(stderr, "Invalid test data received");
    exit(-1);
  }
  return (1);
}

static int
resolver_alloc_cb_pass (void *resolver_data, void *user_data)
{
  cb_count++;
  if(strcmp(user_data, TEST_DATA_STRING)) {
    fprintf(stderr, "Invalid test data received");
    exit(-1);
  }
  return (0);
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  res = curl_easy_setopt(curl_easy, CURLOPT_RESOLVER_START_DATA,
    TEST_DATA_STRING);
  if(res != CURLE_OK) {
    fprintf(stderr, "Error setting CURLOPT_RESOLVER_START_DATA\n");
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_POSTFIELDS, NULL);
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(curl, CURLOPT_HEADER, 1L); /* include header */

  /* Connection should fail since this CB returns 1 */
  res = curl_easy_setopt(curl_easy, CURLOPT_RESOLVER_START_FUNCTION,
    resolver_alloc_cb_fail);
  if(res != CURLE_OK) {
    fprintf(stderr, "Error setting CURLOPT_RESOLVER_START_FUNCTION\n");
  }

  res = curl_easy_perform(curl);
  if(res != CURLE_COULDNT_RESOLVE_HOST) {
    res = CURLE_NOT_BUILT_IN;
    goto test_cleanup;
  }

  /* Try with the CB returning 0 - Connection should succeed */
  res = curl_easy_setopt(curl_easy, CURLOPT_RESOLVER_START_FUNCTION,
    resolver_alloc_cb_pass);
  if(res != CURLE_OK) {
    fprintf(stderr, "Error setting CURLOPT_RESOLVER_START_FUNCTION\n");
  }
  res = curl_easy_perform(curl);

  if(cb_count == 0) {
    fprintf(stderr, "No resolver CB was called\n");
    res = CURLE_NOT_BUILT_IN;
  }
test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
