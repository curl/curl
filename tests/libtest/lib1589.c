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
 * argv3 = proxy1 port
 * argv4 = proxy2 port
 * argv5 = proxyuser:password
 */

#include "first.h"

static CURLcode init1589(CURL *curl, const char *url,
                         const char *userpwd, const char *proxy,
                         int port)
{
  CURLcode result = CURLE_OK;

  res_easy_setopt(curl, CURLOPT_URL, url);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXY, proxy);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXYPORT, (long)port);
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

static CURLcode run1589(CURL *curl, const char *url, const char *userpwd,
                        const char *proxy, int port)
{
  CURLcode result = CURLE_OK;

  result = init1589(curl, url, userpwd, proxy, port);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

static CURLcode test_lib1589(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  const char *proxy = libtest_arg2;
  /* !checksrc! disable BANNEDFUNC 2 */
  int port1 = atoi(libtest_arg3);
  int port2 = atoi(libtest_arg4);
  const char *proxyuserpwd = libtest_arg5;

  if(test_argc < 5)
    return TEST_ERR_MAJOR_BAD;

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

  result = run1589(curl, URL, proxyuserpwd, proxy, port1);
  if(result)
    goto test_cleanup;

  curl_mfprintf(stderr, "lib1589: now we do the request again\n");

  result = run1589(curl, URL, proxyuserpwd, proxy, port2);

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
