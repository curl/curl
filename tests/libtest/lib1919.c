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

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl;
  int i;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);
  easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
  easy_setopt(curl, CURLOPT_XOAUTH2_BEARER,
                   "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca1");
  easy_setopt(curl, CURLOPT_SASL_AUTHZID,
                   "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca2");
  easy_setopt(curl, CURLOPT_URL, URL);

  for(i = 0; i < 2; i++) {
    /* the second request needs to do connection reuse */
    res = curl_easy_perform(curl);
    if(res)
      goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
