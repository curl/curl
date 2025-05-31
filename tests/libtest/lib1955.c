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
#include "test.h"

#include "memdebug.h"

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = TEST_ERR_MAJOR_BAD;
  struct curl_slist *list = NULL;
  struct curl_slist *connect_to = NULL;

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

  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_AWS_SIGV4, "xxx");
  test_setopt(curl, CURLOPT_USERPWD, "xxx");
  test_setopt(curl, CURLOPT_HEADER, 0L);
  test_setopt(curl, CURLOPT_URL, URL);
  list = curl_slist_append(list, "test3: 1234");
  if(!list)
    goto test_cleanup;
  if(libtest_arg2) {
    connect_to = curl_slist_append(connect_to, libtest_arg2);
  }
  test_setopt(curl, CURLOPT_CONNECT_TO, connect_to);
  curl_slist_append(list, "Content-Type: application/json");

  /* 'name;' user headers with no value are used to send an empty header in the
     format 'name:' (note the semi-colon becomes a colon). this entry should
     show in SignedHeaders without an additional semi-colon, as any other
     header would. eg 'foo;test2;test3' and not 'foo;test2;;test3'. */
  curl_slist_append(list, "test2;");

  /* 'name:' user headers with no value are used to signal an internal header
     of that name should be removed and are not sent as a header. this entry
     should not show in SignedHeaders. */
  curl_slist_append(list, "test1:");

  /* 'name' user headers with no separator or value are invalid and ignored.
     this entry should not show in SignedHeaders. */
  curl_slist_append(list, "test0");

  curl_slist_append(list, "test_space: t\ts  m\t   end    ");
  curl_slist_append(list, "tesMixCase: MixCase");
  test_setopt(curl, CURLOPT_HTTPHEADER, list);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(connect_to);
  curl_slist_free_all(list);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
