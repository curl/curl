/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

#include "testtrace.h"

static size_t sink2504(char *ptr, size_t size, size_t nmemb, void *ud)
{
  (void)ptr;
  (void)ud;
  return size * nmemb;
}

static void dump_cookies2504(CURL *h, const char *tag)
{
  struct curl_slist *cookies = NULL;
  struct curl_slist *nc;
  CURLcode rc = curl_easy_getinfo(h, CURLINFO_COOKIELIST, &cookies);

  curl_mprintf("== %s ==\n", tag);
  if(rc) {
    curl_mprintf("getinfo error: %d\n", (int)rc);
    return;
  }
  for(nc = cookies; nc; nc = nc->next)
    puts(nc->data);
  curl_slist_free_all(cookies);
}

static CURLcode test_lib2504(const char *URL)
{
  CURL *curl;
  CURLcode result;
  struct curl_slist *hdrs = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  hdrs = curl_slist_append(hdrs, "Host: victim.internal");

  test_setopt(curl, CURLOPT_WRITEFUNCTION, sink2504);
  test_setopt(curl, CURLOPT_COOKIEFILE, "");
  test_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  test_setopt(curl, CURLOPT_URL, URL);

  result = curl_easy_perform(curl);
  curl_mprintf("req1=%d\n", (int)result);
  dump_cookies2504(curl, "after request 1");

  test_setopt(curl, CURLOPT_HTTPHEADER, NULL);
  test_setopt(curl, CURLOPT_URL, URL);

  result = curl_easy_perform(curl);
  curl_mprintf("req2=%d\n", (int)result);
  dump_cookies2504(curl, "after request 2");
test_cleanup:
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
