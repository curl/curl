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

/* RFC 9421 Appendix B.2.6 test vector: Ed25519 signing of a POST request
 * with headers. Uses CURL_HTTPSIG_CREATED=1618884473 to match the RFC
 * expected timestamp. */

#include "first.h"

static CURLcode test_lib5004(const char *URL)
{
  CURL *curl;
  CURLcode result = TEST_ERR_MAJOR_BAD;
  struct curl_slist *connect_to = NULL;
  struct curl_slist *headers = NULL;

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

  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HTTPSIG, (long)CURLHTTPSIG_ED25519);
  test_setopt(curl, CURLOPT_HTTPSIG_KEY,
              "9f8362f87a484a954e6e740c5b4c0e84"
              "229139a20aa8ab56ff66586f6a7d29c5");
  test_setopt(curl, CURLOPT_HTTPSIG_KEYID, "test-key-ed25519");
  test_setopt(curl, CURLOPT_HTTPSIG_HEADERS,
              "date @method @path @authority content-type content-length");
  test_setopt(curl, CURLOPT_POSTFIELDS, "{\"hello\": \"world\"}");

  headers = curl_slist_append(headers,
                              "Date: Tue, 20 Apr 2021 02:07:55 GMT");
  headers = curl_slist_append(headers,
                              "Content-Type: application/json");
  headers = curl_slist_append(headers,
                              "Content-Length: 18");
  test_setopt(curl, CURLOPT_HTTPHEADER, headers);

  test_setopt(curl, CURLOPT_HEADER, 0L);
  test_setopt(curl, CURLOPT_URL, URL);
  if(libtest_arg2) {
    connect_to = curl_slist_append(connect_to, libtest_arg2);
  }
  test_setopt(curl, CURLOPT_CONNECT_TO, connect_to);

  result = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(headers);
  curl_slist_free_all(connect_to);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
