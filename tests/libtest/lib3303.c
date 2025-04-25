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

/* testing the CURLALTSVC_NO_RETRY flag */

#include "test.h"
#include "memdebug.h"

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  long flag = CURLALTSVC_NO_RETRY |
    CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_ALTSVC, "log/altsvc-TESTNUMBER");
  test_setopt(curl, CURLOPT_ALTSVC_CTRL, flag);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
