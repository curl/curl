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

static CURLcode test_lib1965(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURLUcode rc;
  const char *schemes[] = {
    "bad!", "bad{", "bad/", "bad\\", "a!",
    "a+123", "http-2", "http.1",
    "a+-.123", "http-+++2", "http.1--",
    "+a123", "-http2", ".http1",
    "ABC2", "2CBA", "", "a",
    "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd",
    "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddde",
    NULL};
  int i;
  (void) URL;

  global_init(CURL_GLOBAL_ALL);

  for(i = 0; schemes[i]; i++) {
    CURLU *url = curl_url();
    rc = curl_url_set(url, CURLUPART_SCHEME, schemes[i],
                      CURLU_NON_SUPPORT_SCHEME);
    curl_mprintf("%s %s\n", schemes[i],
                 rc == CURLUE_OK ? "ACCEPTED" : "REJECTED");
    curl_url_cleanup(url);
  }

  curl_global_cleanup();
  return result;
}
