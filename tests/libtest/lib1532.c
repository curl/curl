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

#include "memdebug.h"

/* Test CURLINFO_RESPONSE_CODE */

CURLcode test(char *URL)
{
  CURL *curl;
  long httpcode;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);
  if(res) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
  if(res) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_getinfo() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }
  if(httpcode != 200) {
    curl_mfprintf(stderr, "%s:%d unexpected response code %ld\n",
                  __FILE__, __LINE__, httpcode);
    res = CURLE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

  /* Test for a regression of github bug 1017 (response code does not reset) */
  curl_easy_reset(curl);

  res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
  if(res) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_getinfo() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }
  if(httpcode) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_reset failed to zero the response code\n"
                  "possible regression of github bug 1017\n",
                  __FILE__, __LINE__);
    res = CURLE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
