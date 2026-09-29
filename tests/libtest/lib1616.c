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
/*
 * argv1 = URL fetched through the proxy
 * argv2 = proxy host
 * argv3 = proxy port
 * argv4 = test number
 */

#include "first.h"

static CURLcode test_lib1616(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  char proxy[128];
  char direct[256];
  char tunneled[256];

  if(test_argc < 4)
    return TEST_ERR_MAJOR_BAD;

  curl_msnprintf(proxy, sizeof(proxy), "http://%s:%s",
                 libtest_arg2, libtest_arg3);
  curl_msnprintf(direct, sizeof(direct), "http://%s:%s/%s0002",
                 libtest_arg2, libtest_arg3, libtest_arg4);
  curl_msnprintf(tunneled, sizeof(tunneled),
                 "http://test.remote.example.com:%s/%s0004",
                 libtest_arg3, libtest_arg4);

  res_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  start_test_timing();

  easy_setopt(curl, CURLOPT_PROXY, proxy);
  easy_setopt(curl, CURLOPT_NOPROXY, libtest_arg2);
  easy_setopt(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_DIGEST);
  easy_setopt(curl, CURLOPT_PROXYUSERPWD, "silly:person");

  easy_setopt(curl, CURLOPT_URL, URL);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* the excluded host is reached directly and answers 407 */
  easy_setopt(curl, CURLOPT_URL, direct);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* the same proxy as before must not get a Proxy-Authorization header */
  easy_setopt(curl, CURLOPT_URL, URL);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* an origin reached through a CONNECT tunnel answers 407 as well */
  easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  easy_setopt(curl, CURLOPT_URL, tunneled);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* and that must not reach the proxy either */
  easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 0L);
  easy_setopt(curl, CURLOPT_URL, URL);
  result = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
