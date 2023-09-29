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

#include "testtrace.h"
#include "memdebug.h"

int test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *hnd;
  global_init(CURL_GLOBAL_ALL);

  easy_init(hnd);
  easy_setopt(hnd, CURLOPT_URL, URL);
  easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  easy_setopt(hnd, CURLOPT_HEADER, 1L);

  res = curl_easy_perform(hnd);
  if(res)
    goto test_cleanup;

  curl_easy_setopt(hnd, CURLOPT_URL, libtest_arg2);
  res = curl_easy_perform(hnd);

test_cleanup:
  curl_easy_cleanup(hnd);
  curl_global_cleanup();
  return (int)res;
}
