/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2021 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
  CURLcode ret;
  CURL *hnd;
  curl_global_init(CURL_GLOBAL_ALL);

  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, URL);
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_HEADER, 1L);

  ret = curl_easy_perform(hnd);

  curl_easy_setopt(hnd, CURLOPT_URL, libtest_arg2);
  ret = curl_easy_perform(hnd);
  curl_easy_cleanup(hnd);

  curl_global_cleanup();
  return (int)ret;
}
