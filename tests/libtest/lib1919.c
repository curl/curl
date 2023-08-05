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
  CURL *curl;
  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    int i;
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER,
                     "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca1");
    curl_easy_setopt(curl, CURLOPT_SASL_AUTHZID,
                     "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca2");
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    for(i = 0; i < 2; i++)
      /* the second request needs to do connection reuse */
      curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}
