/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Nicolas Sterchele, <nicolas@sterchelen.net>
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

static CURLcode test_lib3010(const char *URL)
{
  CURLcode result = TEST_ERR_MAJOR_BAD;
  CURL *curl = NULL;
  curl_off_t retry_after;
  const char *follow_url = NULL;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    result = curl_easy_perform(curl);
    if(result) {
      curl_mfprintf(stderr,
                    "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                    __FILE__, __LINE__, result, curl_easy_strerror(result));
      goto test_cleanup;
    }
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &follow_url);
    curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
    curl_mprintf("Retry-After %" CURL_FORMAT_CURL_OFF_T "\n", retry_after);
    curl_easy_setopt(curl, CURLOPT_URL, follow_url);
    result = curl_easy_perform(curl);
    if(result) {
      curl_mfprintf(stderr,
                    "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                    __FILE__, __LINE__, result, curl_easy_strerror(result));
      goto test_cleanup;
    }

    curl_easy_reset(curl);
    curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
    curl_mprintf("Retry-After %" CURL_FORMAT_CURL_OFF_T "\n", retry_after);
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
