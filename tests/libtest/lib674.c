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

static CURLcode test_lib674(const char *URL)
{
  CURL *handle = NULL;
  CURL *handle2;
  CURLcode res = CURLE_OK;
  CURLU *urlp = NULL;
  CURLUcode uc = CURLUE_OK;

  global_init(CURL_GLOBAL_ALL);
  easy_init(handle);

  urlp = curl_url();

  if(!urlp) {
    curl_mfprintf(stderr, "problem init URL api.");
    goto test_cleanup;
  }

  uc = curl_url_set(urlp, CURLUPART_URL, URL, 0);
  if(uc) {
    curl_mfprintf(stderr, "problem setting CURLUPART_URL: %s.",
                  curl_url_strerror(uc));
    goto test_cleanup;
  }

  /* demonstrate override behavior */

  easy_setopt(handle, CURLOPT_CURLU, urlp);
  easy_setopt(handle, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(handle);

  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_easy_perform() failed "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  handle2 = curl_easy_duphandle(handle);
  res = curl_easy_perform(handle2);
  curl_easy_cleanup(handle2);

test_cleanup:

  curl_url_cleanup(urlp);
  curl_easy_cleanup(handle);
  curl_global_cleanup();

  return res;
}
