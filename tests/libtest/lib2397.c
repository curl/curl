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

static CURLcode test_lib2397(const char *URL)
{
  CURLcode result;
  CURL *curl;
  char *referer = NULL;

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

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);

  result = curl_easy_perform(curl);
  if(result)
    curl_mfprintf(stderr, "transfer failed: %s\n", curl_easy_strerror(result));
  else
    result = curl_easy_getinfo(curl, CURLINFO_REFERER, &referer);

  if(!referer)
    curl_mfprintf(stderr, "CURLINFO_REFERER was not populated\n");
  else
    result = curl_easy_setopt(curl, CURLOPT_REFERER, referer);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
