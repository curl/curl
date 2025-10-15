/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) James Fuller, <jim@webcomposite.com>, et al.
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
 * Set maximum number of persistent connections to 1.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    const char *urls[] = { "https://example.com",
      "https://curl.se",
      "https://www.example/",
      NULL /* end of list */
    };
    int i = 0;

    /* Change the maximum number of persistent connection   */
    curl_easy_setopt(curl, CURLOPT_MAXCONNECTS, 1L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* loop over the URLs */
    while(urls[i]) {
      curl_easy_setopt(curl, CURLOPT_URL, urls[i]);

      /* Perform the request, res gets the return code */
      res = curl_easy_perform(curl);
      /* Check for errors */
      if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
      i++;
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
