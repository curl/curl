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
 * argv1 = the first URL
 * argv2 = URL2
 * argv3 = credentials 1
 * argv4 = credentials 2
 */

#include "first.h"

/* this is meant to pick up the proxy from the environment variable */
static CURLcode init1647(CURL *curl, const char *url, const char *userpwd)
{
  CURLcode result = CURLE_OK;

  res_easy_setopt(curl, CURLOPT_URL, url);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXYUSERPWD, userpwd);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if(result)
    goto init_failed;

  return CURLE_OK; /* success */

init_failed:
  return result; /* failure */
}

static CURLcode run1647(CURL *curl, const char *url, const char *userpwd)
{
  CURLcode result = CURLE_OK;

  result = init1647(curl, url, userpwd);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

static CURLcode test_lib1647(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;

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

  curl_mprintf("--- First get '%s'\n", URL);
  result = run1647(curl, URL, libtest_arg3);
  if(result)
    goto test_cleanup;

  curl_mprintf("--- Then get '%s'\n", libtest_arg2);
  result = run1647(curl, libtest_arg2, libtest_arg4);

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
