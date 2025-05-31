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
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *connect_to = NULL;
  struct curl_slist *list = NULL, *tmp;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_AWS_SIGV4, "xxx");
  easy_setopt(curl, CURLOPT_URL, URL);
  if(libtest_arg2) {
    connect_to = curl_slist_append(connect_to, libtest_arg2);
    if(!connect_to) {
      res = CURLE_FAILED_INIT;
      goto test_cleanup;
    }
  }
  easy_setopt(curl, CURLOPT_CONNECT_TO, connect_to);
  list = curl_slist_append(list, "Content-Type: application/json");
  tmp = curl_slist_append(list, "X-Xxx-Date: 19700101T000000Z");
  if(!list || !tmp) {
    res = CURLE_FAILED_INIT;
    goto test_cleanup;
  }
  list = tmp;
  easy_setopt(curl, CURLOPT_HTTPHEADER, list);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(connect_to);
  curl_slist_free_all(list);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
