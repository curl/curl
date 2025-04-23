/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Vijay Panghal, <vpanghal@maginatics.com>, et al.
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

/*
 * This unit test PUT http data over proxy. Same  http header will be generated
 * for server and proxy
 */

#include "test.h"

#include "memdebug.h"

static char testdata[] = "Hello Cloud!\n";

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t  amount = nmemb * size; /* Total bytes curl wants */
  if(amount < strlen(testdata)) {
    return strlen(testdata);
  }
  (void)stream;
  memcpy(ptr, testdata, strlen(testdata));
  return strlen(testdata);
}


CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_FAILED_INIT;
  /* http header list */
  struct curl_slist *hhl = NULL, *tmp = NULL;

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

  hhl = curl_slist_append(hhl, "User-Agent: Http Agent");
  if(!hhl) {
    goto test_cleanup;
  }
  tmp = curl_slist_append(hhl, "Expect: 100-continue");
  if(!tmp) {
    goto test_cleanup;
  }
  hhl = tmp;

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  test_setopt(curl, CURLOPT_HTTPHEADER, hhl);
  test_setopt(curl, CURLOPT_POST, 0L);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_PROXYTYPE, (long)CURLPROXY_HTTP);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
  test_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  test_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  test_setopt(curl, CURLOPT_INFILESIZE, (long)strlen(testdata));
  test_setopt(curl, CURLOPT_HEADEROPT, (long)CURLHEADER_UNIFIED);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);

  curl_slist_free_all(hhl);

  curl_global_cleanup();

  return res;
}
