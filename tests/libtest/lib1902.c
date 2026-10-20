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

static CURLcode test_lib1902(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl;
  struct curl_slist *cookies = NULL;
  struct curl_slist *cookie;
  bool long_found = FALSE;
  bool short_found = FALSE;
  size_t count = 0;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(!curl) {
    result = TEST_ERR_EASY_INIT;
    goto test_cleanup;
  }
  easy_setopt(curl, CURLOPT_COOKIEFILE, URL);
  easy_setopt(curl, CURLOPT_COOKIEJAR, URL);

  /* The original case: no transfer means no cookie jar write. */
  curl_easy_cleanup(curl);
  curl = curl_easy_init();
  if(!curl) {
    result = TEST_ERR_EASY_INIT;
    goto test_cleanup;
  }

  /* Explicitly reload the same jar, also without starting a transfer. */
  easy_setopt(curl, CURLOPT_COOKIEFILE, URL);
  easy_setopt(curl, CURLOPT_COOKIELIST, "RELOAD");
  result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
  if(result)
    goto test_cleanup;
  for(cookie = cookies; cookie; cookie = cookie->next) {
    if(strstr(cookie->data, "\tlong\tvalue"))
      long_found = strlen(cookie->data) > 5048;
    if(strstr(cookie->data, "\thas_js\t1"))
      short_found = TRUE;
    count++;
  }
  if(count != 2 || !long_found || !short_found)
    result = TEST_ERR_FAILURE;

test_cleanup:
  curl_slist_free_all(cookies);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
