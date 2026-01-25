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

static CURLcode test_lib3027(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl;
  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    result = curl_easy_perform(curl);
    if(result == CURLE_OK) {
      long filetime;
      result = curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      /* MTDM fails with 550, so filetime should be -1 */
      if((result == CURLE_OK) && (filetime != -1)) {
        /* we just need to return something which is not CURLE_OK */
        result = CURLE_UNSUPPORTED_PROTOCOL;
      }
    }
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return result;
}
