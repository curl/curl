/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static CURLcode user_verify_status_callback(CURL *curl, void *ssl,
                                            void *userptr)
{
  (void)curl; /* unused */
  (void)ssl; /* unused */
  int *callback_was_called = (int *)userptr;

  *callback_was_called = 1;

  /* do some ssl calls here */

  return CURLE_OK;
}

int test(char *URL)
{
  int res = 0;
  CURL *curl = NULL;
  int callback_was_called = 0;

  start_test_timing();

  res_global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
  easy_setopt(
    curl, CURLOPT_SSL_VERIFYSTATUS_FUNCTION, &user_verify_status_callback);
  easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS_DATA, &callback_was_called);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return callback_was_called ? 0 : 1;
}
