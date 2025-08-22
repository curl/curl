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

static CURLcode test_lib1538(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURLcode easyret;
  CURLMcode multiret;
  CURLSHcode shareret;
  CURLUcode urlret;
  (void)URL;

  /* NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
  curl_easy_strerror((CURLcode)INT_MAX);
  curl_multi_strerror((CURLMcode)INT_MAX);
  curl_share_strerror((CURLSHcode)INT_MAX);
  curl_url_strerror((CURLUcode)INT_MAX);
  curl_easy_strerror((CURLcode)-INT_MAX);
  curl_multi_strerror((CURLMcode)-INT_MAX);
  curl_share_strerror((CURLSHcode)-INT_MAX);
  curl_url_strerror((CURLUcode)-INT_MAX);
  /* NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
  for(easyret = CURLE_OK; easyret <= CURL_LAST; easyret++) {
    curl_mprintf("e%d: %s\n", easyret, curl_easy_strerror(easyret));
  }
  for(multiret = CURLM_CALL_MULTI_PERFORM; multiret <= CURLM_LAST;
      multiret++) {
    curl_mprintf("m%d: %s\n", multiret, curl_multi_strerror(multiret));
  }
  for(shareret = CURLSHE_OK; shareret <= CURLSHE_LAST; shareret++) {
    curl_mprintf("s%d: %s\n", shareret, curl_share_strerror(shareret));
  }
  for(urlret = CURLUE_OK; urlret <= CURLUE_LAST; urlret++) {
    curl_mprintf("u%d: %s\n", urlret, curl_url_strerror(urlret));
  }

  return res;
}
