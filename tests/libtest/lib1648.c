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
 * URL = host
 * arg2 = port
 */

#include "first.h"

/* this is meant to pick up the proxy from the environment variable */
static CURLcode init1648(CURL *curl, const char *url, const char *proxy)
{
  CURLcode result = CURLE_OK;

  res_easy_setopt(curl, CURLOPT_URL, url);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXY, proxy);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if(result)
    goto init_failed;

  return CURLE_OK; /* success */

init_failed:
  return result; /* failure */
}

static CURLcode run1648(CURL *curl, const char *url, const char *userpwd)
{
  CURLcode result = CURLE_OK;

  result = init1648(curl, url, userpwd);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

#define GET_THIS "http://example.com/"

/*
 * First get the URL over 'firstproxy' with auth.
 * Then clear the auth and get the URL again over 'secondproxy'.
 */
static CURLcode test_lib1648(const char *hostip)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  struct curl_slist *host = NULL;
  struct curl_slist *host2 = NULL;
  char proxy1_resolve[128];
  char proxy2_resolve[128];
  char proxy1_connect[128];
  char proxy2_connect[128];

  curl_msnprintf(proxy1_resolve, sizeof(proxy1_resolve),
                 "firstproxy:%s:%s", libtest_arg2, hostip);
  curl_msnprintf(proxy2_resolve, sizeof(proxy2_resolve),
                 "secondproxy:%s:%s", libtest_arg2, hostip);

  /* we connect to the fake host name but the right port number */
  curl_msnprintf(proxy1_connect, sizeof(proxy1_connect),
                 "firstproxy:%s", libtest_arg2);
  curl_msnprintf(proxy2_connect, sizeof(proxy2_connect),
                 "secondproxy:%s", libtest_arg2);

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
  easy_setopt(curl, CURLOPT_PROXYUSERPWD, "victim:secret");

  curl_mprintf("--- First get over %s\n", proxy1_connect);
  result = run1648(curl, GET_THIS, proxy1_connect);
  if(result)
    goto test_cleanup;

  easy_setopt(curl, CURLOPT_PROXYUSERPWD, NULL);

  curl_mprintf("--- Then over '%s'\n", proxy2_connect);
  result = run1648(curl, GET_THIS, proxy2_connect);

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl_slist_free_all(host);
  return result;
}
