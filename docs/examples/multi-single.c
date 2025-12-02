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
 * using the multi interface to do a single download
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

/*
 * Simply download an HTTP file.
 */
int main(void)
{
  CURL *curl;

  CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
  if(res)
    return (int)res;

  curl = curl_easy_init();
  if(curl) {

    CURLM *multi;
    int still_running = 1; /* keep number of running handles */

    /* set the options (I left out a few, you get the point anyway) */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");

    /* init a multi stack */
    multi = curl_multi_init();
    if(multi) {

      /* add the individual transfers */
      curl_multi_add_handle(multi, curl);

      do {
        CURLMcode mc = curl_multi_perform(multi, &still_running);

        if(!mc)
          /* wait for activity, timeout or "nothing" */
          mc = curl_multi_poll(multi, NULL, 0, 1000, NULL);

        if(mc) {
          fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int)mc);
          break;
        }

      } while(still_running);

      curl_multi_remove_handle(multi, curl);

      curl_multi_cleanup(multi);
    }

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
