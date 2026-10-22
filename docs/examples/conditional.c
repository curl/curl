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
/* <DESC>
 * Use CURLOPT_TIMEVALUE to perform a conditional HTTP request.
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    long unmet = 0;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* January 1, 2020 00:00:00 UTC */
    curl_easy_setopt(curl, CURLOPT_TIMEVALUE, 1577836800L);

    /* If-Modified-Since the above timestamp */
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION,
                     (long)CURL_TIMECOND_IFMODSINCE);

    result = curl_easy_perform(curl);
    if(result != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));
    }
    else {
      /* Check whether the condition was met or unmet
         (e.g. 304 Not Modified) */
      if(curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet) == CURLE_OK)
        printf("Condition was %sfulfilled\n", unmet ? "NOT " : "");
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return (int)result;
}
