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

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURLSH *share;
  CURL *curl;

  curl_global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);

  curl = curl_easy_init();
  test_setopt(curl, CURLOPT_SHARE, share);

  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_PROXY, URL);
  test_setopt(curl, CURLOPT_URL, "http://example.com/");

  test_setopt(curl, CURLOPT_COOKIEFILE, "");

  test_setopt(curl, CURLOPT_COOKIELIST,
              "example.com\tFALSE\t/\tFALSE\t0\tname\tvalue");

  res = curl_easy_perform(curl);
  if(res) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_share_cleanup(share);
  curl_global_cleanup();

  return res;
}
