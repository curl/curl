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

/*
 * A session id learned from one origin must not be sent to another one
 * after a redirect.
 */
static CURLcode test_lib3233(const char *URL)
{
  CURLcode result;
  CURL *curl;
  struct curl_slist *resolve = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  resolve = curl_slist_append(resolve, libtest_arg2);

  easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
  easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, URL);
  easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "rtsp");
  easy_setopt(curl, CURLOPT_RESOLVE, resolve);

  result = curl_easy_perform(curl);

test_cleanup:

  curl_slist_free_all(resolve);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
