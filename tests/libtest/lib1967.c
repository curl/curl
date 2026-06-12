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

static CURLcode test_lib1967(const char *URL)
{
  CURLU *u = curl_url();
  (void)URL;
  if(u) {
    char *url;
    curl_url_set(u, CURLUPART_URL, "a.b", CURLU_GUESS_SCHEME);
    curl_url_set(u, CURLUPART_URL, "/x", CURLU_NO_GUESS_SCHEME);

    if(!curl_url_get(u, CURLUPART_URL, &url, 0)) {
      curl_mprintf("URL %s\n", url);
      curl_free(url);
    }
    curl_url_cleanup(u);
  }
  return CURLE_OK;
}
