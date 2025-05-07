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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

CURLcode test(char *URL)
{
  CURL *curls = NULL;
  CURLM *multi = NULL;
  CURLcode i = CURLE_OK;
  CURLcode res = CURLE_OK;
  CURLMcode mc;

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  easy_init(curls);

  easy_setopt(curls, CURLOPT_URL, URL);

  multi_add_handle(multi, curls);

  mc = curl_multi_remove_handle(multi, curls);
  mc += curl_multi_remove_handle(multi, curls);

  if(mc) {
    curl_mfprintf(stderr, "%d was unexpected\n", (int)mc);
    i = CURLE_FAILED_INIT;
  }

test_cleanup:
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curls);
  curl_global_cleanup();

  if(res)
    i = res;

  return i; /* return the final return code */
}
