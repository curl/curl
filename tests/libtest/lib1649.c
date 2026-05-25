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

/* this is meant to pick up the proxy from the environment variable */
static CURLcode init1649(CURL *curl, const char *url)
{
  CURLcode result = CURLE_OK;

  res_easy_setopt(curl, CURLOPT_URL, url);
  if(result)
    goto init_failed;

  res_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if(result)
    goto init_failed;

  return CURLE_OK; /* success */

init_failed:
  return result; /* failure */
}

static CURLcode run1649(CURL *curl, const char *url)
{
  CURLcode result = CURLE_OK;

  result = init1649(curl, url);
  if(result)
    return result;

  return curl_easy_perform(curl);
}

static CURLcode test_lib1649(const char *URL)
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

  easy_setopt(curl, CURLOPT_REFERER, "https://secret.example.com/");

  result = run1649(curl, URL);
  if(result)
    goto test_cleanup;

  /* reset it */
  easy_setopt(curl, CURLOPT_REFERER, NULL);

  result = run1649(curl, URL);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
