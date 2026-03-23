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
#include "unitcheck.h"

#include "urldata.h"

static CURLcode test_unit3218(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_SPNEGO
  {
    CURL *easy;
    CURLcode res;
    CURLcode result = CURLE_OK;
    struct Curl_easy *data;

    global_init(CURL_GLOBAL_ALL);
    easy = curl_easy_init();
    abort_unless(easy != NULL, "curl_easy_init failed");
    data = (struct Curl_easy *)easy;

    /* verify default is FALSE */
    fail_unless(data->set.spnego_fail_on_error == FALSE,
                "SPNEGO fail on error should default to FALSE");

    /* verify setting to 1 works */
    res = curl_easy_setopt(easy, CURLOPT_SPNEGO_FAIL_ON_ERROR, 1L);
    fail_unless(res == CURLE_OK, "setopt SPNEGO_FAIL_ON_ERROR 1 failed");
    fail_unless(data->set.spnego_fail_on_error == TRUE,
                "SPNEGO fail on error should be TRUE after setting 1");

    /* verify setting to 0 works */
    res = curl_easy_setopt(easy, CURLOPT_SPNEGO_FAIL_ON_ERROR, 0L);
    fail_unless(res == CURLE_OK, "setopt SPNEGO_FAIL_ON_ERROR 0 failed");
    fail_unless(data->set.spnego_fail_on_error == FALSE,
                "SPNEGO fail on error should be FALSE after setting 0");

    curl_easy_cleanup(easy);
    curl_global_cleanup();
  }
#endif

  UNITTEST_END_SIMPLE
}
