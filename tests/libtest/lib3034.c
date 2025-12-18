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
#include "first.h"

static const char data_3034[] = "hello";

static size_t t3034_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  size_t len = size * nmemb;
  size_t tocopy = sizeof(data_3034) < len ? sizeof(data_3034) : len;
  (void)userp;
  memcpy(ptr, data_3034, tocopy);
  return tocopy;
}

static CURLcode test_lib3034(const char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  /* This first request will receive a redirect response; deliberately only
   * set the CURLOPT_READFUNCTION but not the CURLOPT_SEEKFUNCTION to force a
   * rewind failure (CURLE_SEND_FAIL_REWIND).
   */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_INFILESIZE, 5L);
  test_setopt(curl, CURLOPT_READFUNCTION, t3034_read_cb);

  res = curl_easy_perform(curl);
  if(res != CURLE_SEND_FAIL_REWIND) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  /* Reset the easy handle, which should clear the rewind failure. */
  curl_easy_reset(curl);

  /* Perform a second request, which should succeed. */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
