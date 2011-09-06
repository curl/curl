/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * This test case is based on the sample code provided by Saqib Ali
 * http://curl.haxx.se/mail/lib-2011-03/0066.html
 */

#include "test.h"

#include <sys/stat.h>

#include "memdebug.h"

int test(char *URL)
{
  int stillRunning;
  CURLM* multiHandle;
  CURL* curl;
  int res1 = 0;
  int res;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if((multiHandle = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_multi_cleanup(multiHandle);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_USERPWD, libtest_arg2);
  test_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "curl_client_key.pub");
  test_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "curl_client_key");

  test_setopt(curl, CURLOPT_UPLOAD, 1);
  test_setopt(curl, CURLOPT_VERBOSE, 1);

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_INFILESIZE, (long)5);

  if((res = (int)curl_multi_add_handle(multiHandle, curl)) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", res);
    curl_easy_cleanup(curl);
    curl_multi_cleanup(multiHandle);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* this tests if removing an easy handle immediately after multi
     perform has been called succeeds or not. */

  fprintf(stderr, "curl_multi_perform()...\n");
  res1 = (int) curl_multi_perform(multiHandle, &stillRunning);
  if(res1)
    fprintf(stderr, "curl_multi_perform() failed, "
            "with code %d\n", res1);
  else
    fprintf(stderr, "curl_multi_perform() succeeded\n");

  fprintf(stderr, "curl_multi_remove_handle()...\n");
  res = (int) curl_multi_remove_handle(multiHandle, curl);
  if(res)
    fprintf(stderr, "curl_multi_remove_handle() failed, "
            "with code %d\n", res);
  else
    fprintf(stderr, "curl_multi_remove_handle() succeeded\n");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multiHandle);
  curl_global_cleanup();

  if(res)
    return res;
  else
    return res1;
}
