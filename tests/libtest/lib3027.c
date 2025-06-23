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

static CURLcode test_lib3027(char *URL)
{
  CURLcode ret = CURLE_OK;
  CURL *hnd;
  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  hnd = curl_easy_init();
  if(hnd) {
    curl_easy_setopt(hnd, CURLOPT_URL, URL);
    curl_easy_setopt(hnd, CURLOPT_FILETIME, 1L);
    ret = curl_easy_perform(hnd);
    if(CURLE_OK == ret) {
      long filetime;
      ret = curl_easy_getinfo(hnd, CURLINFO_FILETIME, &filetime);
      /* MTDM fails with 550, so filetime should be -1 */
      if((CURLE_OK == ret) && (filetime != -1)) {
        /* we just need to return something which is not CURLE_OK */
        ret = CURLE_UNSUPPORTED_PROTOCOL;
      }
    }
    curl_easy_cleanup(hnd);
  }
  curl_global_cleanup();
  return ret;
}
