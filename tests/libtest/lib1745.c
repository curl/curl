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
 * argv1 = FTP URL
 * argv2 = SOCKS5 proxy
 */

#include "first.h"

static CURLcode test_lib1745(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;

  if(test_argc < 2)
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

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  easy_setopt(curl, CURLOPT_PROXYTYPE, (long)CURLPROXY_SOCKS5);
  easy_setopt(curl, CURLOPT_PROXYUSERPWD, "silly:person");

  /* the proxy picks no authentication for the control connection and
     username/password for the data connection */
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* the control connection did not authenticate, so it must not be
     reused for this one */
  easy_setopt(curl, CURLOPT_SOCKS5_AUTH,
              (long)(CURLAUTH_BASIC | CURLAUTH_ONLY));
  result = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
}
