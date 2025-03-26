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
  CURLcode res;
  CURL *curl;
  int testno = atoi(libtest_arg2);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_URL, URL);
  if((testno == 1571) || (testno == 1575) || (testno == 1581)) {
    test_setopt(curl, CURLOPT_POSTFIELDS, "moo");
  }
  if(testno == 1581) {
    test_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_301);
  }

  test_setopt(curl, CURLOPT_CUSTOMREQUEST, "IGLOO");
  if((testno == 1574) || (testno == 1575)) {
    test_setopt(curl, CURLOPT_FOLLOWLOCATION, CURLFOLLOW_FIRSTONLY);
  }
  else {
    test_setopt(curl, CURLOPT_FOLLOWLOCATION, CURLFOLLOW_OBEYCODE);
  }

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
