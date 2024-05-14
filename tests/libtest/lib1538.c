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
  CURLcode res = CURLE_OK;
  CURLcode easyret;
  CURLMcode multiret;
  CURLSHcode shareret;
  CURLUcode urlret;
  (void)URL;

  curl_easy_strerror((CURLcode)INT_MAX);
  curl_multi_strerror((CURLMcode)INT_MAX);
  curl_share_strerror((CURLSHcode)INT_MAX);
  curl_url_strerror((CURLUcode)INT_MAX);
  curl_easy_strerror((CURLcode)-INT_MAX);
  curl_multi_strerror((CURLMcode)-INT_MAX);
  curl_share_strerror((CURLSHcode)-INT_MAX);
  curl_url_strerror((CURLUcode)-INT_MAX);
  for(easyret = CURLE_OK; easyret <= CURL_LAST; easyret++) {
    printf("e%d: %s\n", (int)easyret, curl_easy_strerror(easyret));
  }
  for(multiret = CURLM_CALL_MULTI_PERFORM; multiret <= CURLM_LAST;
      multiret++) {
    printf("m%d: %s\n", (int)multiret, curl_multi_strerror(multiret));
  }
  for(shareret = CURLSHE_OK; shareret <= CURLSHE_LAST; shareret++) {
    printf("s%d: %s\n", (int)shareret, curl_share_strerror(shareret));
  }
  for(urlret = CURLUE_OK; urlret <= CURLUE_LAST; urlret++) {
    printf("u%d: %s\n", (int)urlret, curl_url_strerror(urlret));
  }

  return res;
}
