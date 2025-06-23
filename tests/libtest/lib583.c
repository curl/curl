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
 * This test case is based on the sample code provided by Saqib Ali
 * https://curl.se/mail/lib-2011-03/0066.html
 */

#include "first.h"

#include "memdebug.h"

static CURLcode test_lib583(char *URL)
{
  int stillRunning;
  CURLM *multiHandle = NULL;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  CURLMcode mres;

  assert(test_argc >= 4);

  global_init(CURL_GLOBAL_ALL);

  multi_init(multiHandle);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_USERPWD, libtest_arg2);
  easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE,  test_argv[3]);
  easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, test_argv[4]);

  easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_INFILESIZE, (long)5);

  multi_add_handle(multiHandle, curl);

  /* this tests if removing an easy handle immediately after multi
     perform has been called succeeds or not. */

  curl_mfprintf(stderr, "curl_multi_perform()...\n");

  multi_perform(multiHandle, &stillRunning);

  curl_mfprintf(stderr, "curl_multi_perform() succeeded\n");

  curl_mfprintf(stderr, "curl_multi_remove_handle()...\n");
  mres = curl_multi_remove_handle(multiHandle, curl);
  if(mres) {
    curl_mfprintf(stderr, "curl_multi_remove_handle() failed, "
                  "with code %d\n", (int)mres);
    res = TEST_ERR_MULTI;
  }
  else
    curl_mfprintf(stderr, "curl_multi_remove_handle() succeeded\n");

test_cleanup:

  /* undocumented cleanup sequence - type UB */

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multiHandle);
  curl_global_cleanup();

  return res;
}
