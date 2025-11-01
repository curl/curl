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
 * multi interface code doing two parallel HTTP transfers
 * </DESC>
 */
#include <stdio.h>
#include <string.h>

/* curl stuff */
#include <curl/curl.h>

/*
 * Simply download two HTTP files!
 */
int main(void)
{
  CURL *curl;
  CURL *curl2;

  CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
  if(res)
    return (int)res;

  curl = curl_easy_init();
  curl2 = curl_easy_init();

  if(curl && curl2) {

    CURLM *multi;

    /* set options */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");

    /* set options */
    curl_easy_setopt(curl2, CURLOPT_URL, "http://localhost/");

    /* init a multi stack */
    multi = curl_multi_init();
    if(multi) {

      int still_running = 1; /* keep number of running handles */

      /* add the individual transfers */
      curl_multi_add_handle(multi, curl);
      curl_multi_add_handle(multi, curl2);

      while(still_running) {
        CURLMsg *msg;
        int queued;

        CURLMcode mc = curl_multi_perform(multi, &still_running);

        if(still_running)
          /* wait for activity, timeout or "nothing" */
          mc = curl_multi_poll(multi, NULL, 0, 1000, NULL);

        if(mc)
          break;

        do {
          msg = curl_multi_info_read(multi, &queued);
          if(msg) {
            if(msg->msg == CURLMSG_DONE) {
              /* a transfer ended */
              fprintf(stderr, "Transfer completed\n");
            }
          }
        } while(msg);
      }

      curl_multi_remove_handle(multi, curl);
      curl_multi_remove_handle(multi, curl2);

      curl_multi_cleanup(multi);
    }
  }

  curl_easy_cleanup(curl);
  curl_easy_cleanup(curl2);

  curl_global_cleanup();

  return 0;
}
