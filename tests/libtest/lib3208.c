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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  int still_running;
  CURLcode i = TEST_ERR_FAILURE;
  CURLcode res = CURLE_OK;
  CURLMsg *msg;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  /* no peer verify */
  easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  /* first, make an easy perform with the handle */
  curl_easy_perform(curl);

  /* then proceed and use it for a multi perform */
  multi_add_handle(multi, curl);

  multi_perform(multi, &still_running);

  abort_on_test_timeout();

  while(still_running) {
    CURLMcode mres;
    int num;
    mres = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);
    if(mres != CURLM_OK) {
      printf("curl_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    abort_on_test_timeout();

    multi_perform(multi, &still_running);

    abort_on_test_timeout();
  }

  msg = curl_multi_info_read(multi, &still_running);
  if(msg)
    /* this should now contain a result code from the easy handle,
       get it */
    i = msg->data.result;

  curl_multi_remove_handle(multi, curl);

  /* make a third transfer with the easy handle */
  curl_easy_perform(curl);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  if(res)
    i = res;

  return i; /* return the final return code */
}
