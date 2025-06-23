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

#include "memdebug.h"

/*
 * Get a single URL without select().
 */

static CURLcode test_lib659(char *URL)
{
  CURL *handle = NULL;
  CURLcode res = CURLE_OK;
  CURLU *urlp = NULL;

  global_init(CURL_GLOBAL_ALL);
  easy_init(handle);

  urlp = curl_url();

  if(!urlp) {
    curl_mfprintf(stderr, "problem init URL api.");
    goto test_cleanup;
  }

  /* this doesn't set the PATH part */
  if(curl_url_set(urlp, CURLUPART_HOST, "www.example.com", 0) ||
     curl_url_set(urlp, CURLUPART_SCHEME, "http", 0) ||
     curl_url_set(urlp, CURLUPART_PORT, "80", 0)) {
    curl_mfprintf(stderr, "problem setting CURLUPART");
    goto test_cleanup;
  }

  easy_setopt(handle, CURLOPT_CURLU, urlp);
  easy_setopt(handle, CURLOPT_VERBOSE, 1L);
  easy_setopt(handle, CURLOPT_PROXY, URL);

  res = curl_easy_perform(handle);

  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_easy_perform() failed "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

test_cleanup:

  curl_url_cleanup(urlp);
  curl_easy_cleanup(handle);
  curl_global_cleanup();

  return res;
}
