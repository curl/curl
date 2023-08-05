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

int test(char *URL)
{
  CURLM *curlm = NULL;
  CURL *curl1 = NULL;
  CURL *curl2 = NULL;
  int running_handles = 0;
  int res = 0;

  global_init(CURL_GLOBAL_ALL);

  multi_init(curlm);
  multi_setopt(curlm, CURLMOPT_MAX_HOST_CONNECTIONS, 1);

  easy_init(curl1);
  easy_setopt(curl1, CURLOPT_URL, URL);
  multi_add_handle(curlm, curl1);

  easy_init(curl2);
  easy_setopt(curl2, CURLOPT_URL, URL);
  multi_add_handle(curlm, curl2);

  multi_perform(curlm, &running_handles);

  multi_remove_handle(curlm, curl2);

  /* If curl2 is still in the connect-pending list, this will crash */
  multi_remove_handle(curlm, curl1);

test_cleanup:
  curl_easy_cleanup(curl1);
  curl_easy_cleanup(curl2);
  curl_multi_cleanup(curlm);
  curl_global_cleanup();
  return res;
}
