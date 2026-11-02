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

static void show_effective_url(CURL *curl)
{
  char untouched[] = "untouched";
  char *url = untouched;
  CURLcode result = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
  if(url)
    curl_mprintf("getinfo: %d, url: '%s'\n", (int)result, url);
  else
    curl_mprintf("getinfo: %d, url: (NULL)\n", (int)result);
}

static CURLcode test_lib1990(const char *URL)
{
  CURL *curl;
  CURLcode result;

  (void)URL;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return TEST_ERR_EASY_INIT;
  }

  /* no URL used yet */
  show_effective_url(curl);

  /* an invalid URL with credentials must not be returned */
  curl_easy_setopt(curl, CURLOPT_URL, "http://user:secret@[invalid/");
  result = curl_easy_perform(curl);
  curl_mprintf("perform: %d\n", (int)result);
  show_effective_url(curl);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return CURLE_OK;
}
