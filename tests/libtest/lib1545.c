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

CURLcode test(char *URL)
{
  CURL *eh = NULL;
  CURLcode res = CURLE_OK;
  struct curl_httppost *lastptr = NULL;
  struct curl_httppost *m_formpost = NULL;

  global_init(CURL_GLOBAL_ALL);

  easy_init(eh);

  easy_setopt(eh, CURLOPT_URL, URL);
  CURL_IGNORE_DEPRECATION(
    curl_formadd(&m_formpost, &lastptr, CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, "missing-file", CURLFORM_END);
    curl_easy_setopt(eh, CURLOPT_HTTPPOST, m_formpost);
  )

  (void)curl_easy_perform(eh);
  (void)curl_easy_perform(eh);

test_cleanup:

  CURL_IGNORE_DEPRECATION(
    curl_formfree(m_formpost);
  )
  curl_easy_cleanup(eh);
  curl_global_cleanup();

  return res;
}
