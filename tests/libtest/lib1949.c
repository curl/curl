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

static CURLcode test_lib1949(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  struct curl_header *prev;
  struct curl_header *next;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);

  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  prev = curl_easy_nextheader(curl, CURLH_HEADER, -1, NULL);
  if(!prev) {
    curl_mprintf("no header\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  next = curl_easy_nextheader(curl, CURLH_HEADER, -1, prev);
  curl_mprintf("stale header gives next: %s\n", next ? "yes" : "no");

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
