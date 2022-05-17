/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/multi.h>

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    CURLU *u = curl_url();
    if(u) {
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_url_set(u, CURLUPART_URL, URL, 0);
      curl_easy_setopt(curl, CURLOPT_CURLU, u);
      res = curl_easy_perform(curl);

      fprintf(stderr, "****************************** Do it again\n");
      res = curl_easy_perform(curl);
      curl_url_cleanup(u);
    }
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)res;
}
