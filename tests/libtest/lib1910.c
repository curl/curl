/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

CURLcode test(char *URL)
{
  CURLcode ret = CURLE_OK;
  CURL *hnd;
  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  hnd = curl_easy_init();
  if(hnd) {
    curl_easy_setopt(hnd, CURLOPT_URL, URL);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERPWD, "user\nname:pass\nword");
    ret = curl_easy_perform(hnd);
    curl_easy_cleanup(hnd);
  }
  curl_global_cleanup();
  return ret;
}
