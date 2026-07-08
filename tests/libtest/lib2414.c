/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Dmitry Karpov <dkarpov1970@gmail.com>
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
#include "testtrace.h"

static CURLcode test_lib2414(const char *URL)
{
  CURLM *multi = NULL;
  CURLMcode rc;
  CURLcode result;
  int running;

  (void)URL;
  global_init(CURL_GLOBAL_ALL);

  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_multi_wakeup(multi);
  curl_multi_perform(multi, &running);
  curl_multi_poll(multi, NULL, 0, INT_MAX, NULL);

test_cleanup:
  if(multi)
    curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
}
