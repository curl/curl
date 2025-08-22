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

static CURLcode test_lib694(const char *URL)
{
  CURLcode res;
  CURL *curl;
  long usedauth = 0;
  int count = 0;

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

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HTTPAUTH,
              CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM);
  test_setopt(curl, CURLOPT_USERPWD, "me:password");

  do {

    res = curl_easy_perform(curl);
    if(res)
      goto test_cleanup;

    res = curl_easy_getinfo(curl, CURLINFO_HTTPAUTH_USED, &usedauth);
    if(res)
      goto test_cleanup;
    if(CURLAUTH_NTLM != usedauth) {
      curl_mprintf("CURLINFO_HTTPAUTH_USED did not say NTLM\n");
    }

    /* set a new URL for the second, so that we don't restart NTLM */
    test_setopt(curl, CURLOPT_URL, libtest_arg2);
  } while(!res && ++count < 2);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
