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

static CURLcode test_lib1923(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  CURL *dup = NULL;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);
  easy_setopt(curl, CURLOPT_HSTS, URL);
  easy_setopt(curl, CURLOPT_HSTS_CTRL,
              CURLHSTS_ENABLE | CURLHSTS_READONLYFILE);

  dup = curl_easy_duphandle(curl);
  if(!dup)
    result = CURLE_OUT_OF_MEMORY;

test_cleanup:
  /* Neither handle may rewrite the user-managed HSTS file on cleanup. */
  curl_easy_cleanup(dup);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
