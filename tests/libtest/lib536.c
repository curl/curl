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

static void proxystat(CURL *curl)
{
  long wasproxy;
  if(!curl_easy_getinfo(curl, CURLINFO_USED_PROXY, &wasproxy)) {
    curl_mprintf("This %sthe proxy\n", wasproxy ? "used ":
                 "DID NOT use ");
  }
}

static CURLcode test_lib536(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl;
  struct curl_slist *host = NULL;

  static const char *url_with_proxy = "http://usingproxy.com/";
  const char *url_without_proxy = libtest_arg2;

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

  host = curl_slist_append(NULL, libtest_arg3);
  if(!host)
    goto test_cleanup;

  test_setopt(curl, CURLOPT_RESOLVE, host);
  test_setopt(curl, CURLOPT_PROXY, URL);
  test_setopt(curl, CURLOPT_URL, url_with_proxy);
  test_setopt(curl, CURLOPT_NOPROXY, "goingdirect.com");
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);
  if(!res) {
    proxystat(curl);
    test_setopt(curl, CURLOPT_URL, url_without_proxy);
    res = curl_easy_perform(curl);
    if(!res)
      proxystat(curl);
  }

test_cleanup:

  curl_easy_cleanup(curl);
  curl_slist_free_all(host);
  curl_global_cleanup();

  return res;
}
