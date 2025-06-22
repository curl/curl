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

#include "memdebug.h"

static CURLcode test_lib676(char *URL)
{
  CURLcode res;
  CURL *curl;

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

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_USERAGENT, "the-moo agent next generation");
  test_setopt(curl, CURLOPT_COOKIEFILE, libtest_arg2);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);
  if(res) {
    curl_mfprintf(stderr, "retrieve 1 failed\n");
    goto test_cleanup;
  }

  /* now clear the cookies */
  test_setopt(curl, CURLOPT_COOKIEFILE, NULL);

  res = curl_easy_perform(curl);
  if(res)
    curl_mfprintf(stderr, "retrieve 2 failed\n");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
