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

#include <curl/curl.h>

#define URL2 libtest_arg2

int test(char *URL)
{
  /* first a fine GET response, then a bad one */
  CURL *cl;
  int res = 0;

  global_init(CURL_GLOBAL_ALL);

  cl = curl_easy_init();
  curl_easy_setopt(cl, CURLOPT_URL, URL);
  curl_easy_perform(cl);

  /* re-use handle, do a second transfer */
  curl_easy_setopt(cl, CURLOPT_URL, URL2);
  curl_easy_perform(cl);
  curl_easy_cleanup(cl);
  curl_global_cleanup();
  return res;
}
