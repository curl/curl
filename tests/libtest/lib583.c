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

#include <unistd.h>
#include <sys/stat.h>

int test(char *URL)
{
  CURLMcode retVal;
  int stillRunning;
  CURLM* multiHandle;
  CURL* curl;
  int res;

  curl_global_init(CURL_GLOBAL_ALL);

  multiHandle = curl_multi_init();
  curl = curl_easy_init();

  test_setopt(curl, CURLOPT_USERPWD, libtest_arg2);
  test_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "curl_client_key.pub");
  test_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "curl_client_key");

  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, (long)5);

  curl_multi_add_handle(multiHandle, curl);
  retVal = curl_multi_perform(multiHandle, &stillRunning);
  if (retVal != CURLM_OK)
    fprintf(stderr, "curl_multi_perform() failed!n");

  fprintf(stderr, "curl_multi_remove_handle()!\n");
  retVal = curl_multi_remove_handle(multiHandle, curl);
  if (retVal == CURLM_OK)
    fprintf(stderr, "curl_multi_remove_handle() was successful!\n");
  else
    fprintf(stderr, "curl_multi_remove_handle() failed\n");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multiHandle);

  return res;
}
