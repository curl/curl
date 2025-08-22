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

static CURLcode test_lib1900(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *hnd = NULL;
  CURL *second = NULL;

  global_init(CURL_GLOBAL_ALL);

  easy_init(hnd);
  easy_setopt(hnd, CURLOPT_URL, URL);
  easy_setopt(hnd, CURLOPT_HSTS, "first-hsts.txt");
  easy_setopt(hnd, CURLOPT_HSTS, "second-hsts.txt");

  second = curl_easy_duphandle(hnd);

  curl_easy_cleanup(hnd);
  curl_easy_cleanup(second);
  curl_global_cleanup();
  return CURLE_OK;

test_cleanup:
  curl_easy_cleanup(hnd);
  curl_easy_cleanup(second);
  curl_global_cleanup();
  return res;
}
