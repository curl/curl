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
  static const char * const manual[][2] = {
    { "example.com\tTRUE\t/\tFALSE\t0\thas_js\tfirst",
      "example.com\tTRUE\t/\tFALSE\t0\thas_js\tmanual" },
    { "Set-Cookie: has_js=first; domain=example.com; path=/",
      "Set-Cookie: has_js=manual; domain=example.com; path=/" }
  };
  CURLcode result = CURLE_OK;
  CURL *curl;
  struct curl_slist *cookies = NULL;
  struct curl_slist *cookie;
  size_t i;

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
  curl = NULL;

  /* Reload with and without a live cookie, without starting a transfer. */
  for(i = 0; i <= CURL_ARRAYSIZE(manual); i++) {
    bool long_found = FALSE;
    bool short_found = FALSE;
    size_t count = 0;

    curl = curl_easy_init();
    if(!curl) {
      result = TEST_ERR_EASY_INIT;
      goto test_cleanup;
    }
    easy_setopt(curl, CURLOPT_COOKIEFILE, URL);
    if(i) {
      easy_setopt(curl, CURLOPT_COOKIELIST, manual[i - 1][0]);
      easy_setopt(curl, CURLOPT_COOKIELIST, manual[i - 1][1]);
      result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
      if(result)
        goto test_cleanup;
      if(!cookies || cookies->next) {
        curl_mfprintf(stderr, "cookie file was not deferred\n");
        result = TEST_ERR_FAILURE;
        goto test_cleanup;
      }
      curl_slist_free_all(cookies);
      cookies = NULL;

      /* Manual insertion must not enable jar writes before a transfer. */
      easy_setopt(curl, CURLOPT_COOKIEJAR, URL);
      easy_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");
      easy_setopt(curl, CURLOPT_COOKIEJAR, NULL);
    }
    easy_setopt(curl, CURLOPT_COOKIELIST, "RELOAD");
    result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if(result)
      goto test_cleanup;
    for(cookie = cookies; cookie; cookie = cookie->next) {
      if(strstr(cookie->data, "\tlong\tvalue"))
        long_found = strlen(cookie->data) > 5048;
      if(strstr(cookie->data, i ? "\thas_js\tmanual" : "\thas_js\t1"))
        short_found = TRUE;
      count++;
    }
    if(i && !short_found) {
      curl_mfprintf(stderr, "manual cookie lost priority on reload\n");
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    if(count != 2 || !long_found || !short_found) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    curl_slist_free_all(cookies);
    cookies = NULL;
    curl_easy_cleanup(curl);
    curl = NULL;
  }

test_cleanup:
  curl_slist_free_all(cookies);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
