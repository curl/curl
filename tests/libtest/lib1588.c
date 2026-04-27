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
 * argv1 = URL
 * argv2 = proxy host
 * argv3 = proxy port
 * argv4 = proxyuser:password
 */

#include "first.h"

static CURLcode init1588(CURL *curl, const char *url,
                         const char *userpwd, const char *proxy)
{
  CURLcode result = CURLE_OK;

  res_easy_setopt(curl, CURLOPT_URL, url);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXY, proxy);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXYUSERPWD, userpwd);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if(result)
    goto init_failed;
#if 0
  res_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  if(result)
    goto init_failed;
#endif

  res_easy_setopt(curl, CURLOPT_HEADER, 1L);
  if(result)
    goto init_failed;

  return CURLE_OK; /* success */

init_failed:
  return result; /* failure */
}

static CURLcode run1588(CURL *curl, const char *url, const char *userpwd,
                        const char *proxy)
{
  CURLcode result = CURLE_OK;

  result = init1588(curl, url, userpwd, proxy);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

static CURLcode test_lib1588(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  const char *proxyuserpws = libtest_arg4;
  struct curl_slist *host = NULL;
  struct curl_slist *host2 = NULL;
  char proxy1_resolve[128];
  char proxy2_resolve[128];
  char proxy1_connect[128];
  char proxy2_connect[128];

  if(test_argc < 3)
    return TEST_ERR_MAJOR_BAD;

  curl_msnprintf(proxy1_resolve, sizeof(proxy1_resolve),
                 "firstproxy:%s:%s", libtest_arg3, libtest_arg2);
  curl_msnprintf(proxy2_resolve, sizeof(proxy2_resolve),
                 "secondproxy:%s:%s", libtest_arg3, libtest_arg2);

  /* we connect to the fake host name but the right port number */
  curl_msnprintf(proxy1_connect, sizeof(proxy1_connect),
                 "firstproxy:%s", libtest_arg3);
  curl_msnprintf(proxy2_connect, sizeof(proxy2_connect),
                 "secondproxy:%s", libtest_arg3);

  res_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  host = curl_slist_append(NULL, proxy1_resolve);
  if(!host)
    goto test_cleanup;
  host2 = curl_slist_append(host, proxy2_resolve);
  if(!host2)
    goto test_cleanup;
  host = host2;

  start_test_timing();

  easy_setopt(curl, CURLOPT_RESOLVE, host);

  result = run1588(curl, URL, proxyuserpws, proxy1_connect);
  if(result)
    goto test_cleanup;

  curl_mfprintf(stderr, "lib1588: now we do the request again\n");

  result = run1588(curl, URL, proxyuserpws, proxy2_connect);

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl_slist_free_all(host);
  return result;
}
