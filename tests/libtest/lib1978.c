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

static CURLcode test_lib1978(const char *URL)
{
  CURL *curl;
  CURLcode res = TEST_ERR_MAJOR_BAD;
  struct curl_slist *connect_to = NULL;
  struct curl_slist *list = NULL;

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

  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_INFILESIZE, 0L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");
  test_setopt(curl, CURLOPT_USERPWD, "xxx");
  test_setopt(curl, CURLOPT_HEADER, 0L);
  test_setopt(curl, CURLOPT_URL, URL);

  /* We want to test a couple assumptions here.
     1. the merging works with non-adjacent headers
     2. the merging works across multiple duplicate headers
     3. the merging works if a duplicate header has no colon
     4. the merging works if the headers are cased differently
     5. the merging works across multiple duplicate headers
     6. the merging works across multiple duplicate headers with the
        same value
     7. merging works for headers all with no values
     8. merging works for headers some with no values
  */

  list = curl_slist_append(list, "x-amz-meta-test: test2");
  if(!list)
    goto test_cleanup;
  curl_slist_append(list, "some-other-header: value");
  curl_slist_append(list, "x-amz-meta-test: test1");
  curl_slist_append(list, "duplicate-header: duplicate");
  curl_slist_append(list, "header-no-value");
  curl_slist_append(list, "x-amz-meta-test: test3");
  curl_slist_append(list, "X-amz-meta-test2: test2");
  curl_slist_append(list, "x-amz-meta-blah: blah");
  curl_slist_append(list, "x-Amz-meta-test2: test1");
  curl_slist_append(list, "x-amz-Meta-test2: test3");
  curl_slist_append(list, "curr-header-no-colon");
  curl_slist_append(list, "curr-header-no-colon: value");
  curl_slist_append(list, "next-header-no-colon: value");
  curl_slist_append(list, "next-header-no-colon");
  curl_slist_append(list, "duplicate-header: duplicate");
  curl_slist_append(list, "header-no-value;");
  curl_slist_append(list, "header-no-value;");
  curl_slist_append(list, "header-some-no-value;");
  curl_slist_append(list, "header-some-no-value: value");

  test_setopt(curl, CURLOPT_HTTPHEADER, list);
  if(libtest_arg2) {
    connect_to = curl_slist_append(connect_to, libtest_arg2);
  }
  test_setopt(curl, CURLOPT_CONNECT_TO, connect_to);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(connect_to);
  curl_slist_free_all(list);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
