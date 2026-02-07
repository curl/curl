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
 * Get IMAP email with the multi interface
 * </DESC>
 */
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

/* This is a simple example showing how to fetch mail using libcurl's IMAP
 * capabilities. It builds on the imap-fetch.c example to demonstrate how to
 * use libcurl's multi interface.
 */

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    CURLM *multi;

    multi = curl_multi_init();
    if(multi) {
      int still_running = 1;

      /* Set username and password */
      curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
      curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");

      /* This fetches message 1 from the user's inbox */
      curl_easy_setopt(curl, CURLOPT_URL, "imap://imap.example.com/"
                       "INBOX/;UID=1");

      /* Tell the multi stack about our easy handle */
      curl_multi_add_handle(multi, curl);

      do {
        CURLMcode mresult = curl_multi_perform(multi, &still_running);

        if(still_running)
          /* wait for activity, timeout or "nothing" */
          mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

        if(mresult)
          break;
      } while(still_running);

      /* Always cleanup */
      curl_multi_remove_handle(multi, curl);
      curl_multi_cleanup(multi);
    }
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
