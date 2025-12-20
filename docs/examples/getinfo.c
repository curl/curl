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
 * Use getinfo to get content-type after completed transfer.
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");
    result = curl_easy_perform(curl);

    if(CURLE_OK == result) {
      char *ct;
      /* ask for the content-type */
      result = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

      if((CURLE_OK == result) && ct)
        printf("We received Content-Type: %s\n", ct);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)result;
}
