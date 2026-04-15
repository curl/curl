/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

static size_t sink2505(char *ptr, size_t size, size_t nmemb, void *ud)
{
  (void)ptr;
  (void)ud;
  return size * nmemb;
}

static CURLcode test_lib2505(const char *URL)
{
  CURL *curl;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  struct curl_slist *hdrs = NULL;

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

  test_setopt(curl, CURLOPT_WRITEFUNCTION, sink2505);
  test_setopt(curl, CURLOPT_AUTOREFERER, 1L);
  test_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  test_setopt(curl, CURLOPT_URL, URL);

  result = curl_easy_perform(curl);
  curl_mprintf("req1=%d\n", (int)result);

  test_setopt(curl, CURLOPT_AUTOREFERER, 0L);
  test_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  test_setopt(curl, CURLOPT_URL, URL);

  result = curl_easy_perform(curl);
  curl_mprintf("req2=%d\n", (int)result);

test_cleanup:
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
