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

/*
 * Get a single URL without select().
 */

static CURLcode test_lib751(const char *URL)
{
  CURL *curls[1000];
  CURLM *multi;
  CURLcode res = CURLE_FAILED_INIT;
  CURLMcode mres;
  int i;

  (void)URL;
  memset(curls, 0, sizeof(curls));

  curl_global_init(CURL_GLOBAL_DEFAULT);
  multi = curl_multi_init();
  if(!multi) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  for(i = 0; i < 1000; i++) {
    CURL *curl = curl_easy_init();
    if(!curl) {
      res = CURLE_OUT_OF_MEMORY;
      goto test_cleanup;
    }
    curls[i] = curl;

    res = curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");
    if(!res)
      res = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    if(res)
      goto test_cleanup;

    mres = curl_multi_add_handle(multi, curl);
    if(mres != CURLM_OK) {
      curl_mfprintf(stderr, "MULTI ERROR: %s\n", curl_multi_strerror(mres));
      res = CURLE_FAILED_INIT;
      goto test_cleanup;
    }
  }

test_cleanup:

  if(res)
    curl_mfprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));

  for(i = 0; i < 1000; i++) {
    if(curls[i]) {
      curl_multi_add_handle(multi, curls[i]);
      curl_easy_cleanup(curls[i]);
      curls[i] = NULL;
    }
  }
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return res;
}
