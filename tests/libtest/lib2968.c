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

/*
 * In a build without MD5 support, a Digest challenge that lists nonce
 * before algorithm=MD5 is declined. The half-parsed challenge state
 * must be cleaned up so that a second transfer on the same handle is
 * not affected: https://github.com/curl/curl/issues/24163
 *
 * First URL: 401 with an MD5 Digest challenge (declined, ends in 401)
 * Second URL: 401 with a SHA-256 Digest challenge, then 200
 *
 * With the bug, the second perform fails with
 * CURLE_BAD_CONTENT_ENCODING (61) and the request is never sent.
 */

static CURLcode test_lib2968(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  long httpcode = 0;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
  easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_DIGEST);

  /* first transfer: the MD5 challenge is declined */
  easy_setopt(curl, CURLOPT_URL, URL);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
  if(httpcode != 401) {
    curl_mfprintf(stderr, "first transfer: expected 401, got %ld\n",
                  httpcode);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* second transfer on the same handle: SHA-256 must work */
  easy_setopt(curl, CURLOPT_URL, libtest_arg2);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
  if(httpcode != 200) {
    curl_mfprintf(stderr, "second transfer: expected 200, got %ld\n",
                  httpcode);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
