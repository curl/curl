/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

/*
  Based on a bug report recipe by Rene Bernhardt in
  https://curl.haxx.se/mail/lib-2011-10/0323.html

  It is reproducible by the following steps:

  - Use a proxy that offers NTLM and Negotiate ( CURLOPT_PROXY and
  CURLOPT_PROXYPORT)
  - Tell libcurl NOT to use Negotiate  CURL_EASY_SETOPT(CURLOPT_PROXYAUTH,
  CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM)
  - Start the request
*/

#include "memdebug.h"

int test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_PROXYAUTH,
              (long) (CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM));
  test_setopt(curl, CURLOPT_PROXY, libtest_arg2); /* set in first.c */
  test_setopt(curl, CURLOPT_PROXYUSERPWD, "me:password");

  res = curl_easy_perform(curl);

  test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
