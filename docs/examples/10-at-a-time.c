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
 * Download many files in parallel, in the same thread.
 * </DESC>
 */
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

static const char *urls[] = {
  "https://01.example/",
  "https://02.example/",
  "https://03.example/",
  "https://04.example/",
  "https://05.example/",
  "https://06.example/",
  "https://07.example/",
  "https://08.example/",
  "https://09.example/",
  "https://10.example/",
  "https://11.example/",
  "https://12.example/",
  "https://13.example/",
  "https://14.example/",
  "https://15.example/",
  "https://16.example/",
  "https://17.example/",
  "https://18.example/",
  "https://19.example/",
  "https://20.example/",
  "https://21.example/",
  "https://22.example/",
  "https://23.example/",
  "https://24.example/",
  "https://25.example/",
  "https://26.example/",
  "https://27.example/",
  "https://28.example/",
  "https://29.example/",
  "https://30.example/",
  "https://31.example/",
  "https://32.example/",
  "https://33.example/",
  "https://34.example/",
  "https://35.example/",
  "https://36.example/",
  "https://37.example/",
  "https://38.example/",
  "https://39.example/",
  "https://40.example/",
  "https://41.example/",
  "https://42.example/",
  "https://43.example/",
  "https://44.example/",
  "https://45.example/",
  "https://46.example/",
};

#define MAX_PARALLEL 10  /* number of simultaneous transfers */
#define NUM_URLS     (sizeof(urls) / sizeof(char *))

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n * l;
}

static void add_transfer(CURLM *multi, unsigned int i, int *left)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_URL, urls[i]);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, urls[i]);
    curl_multi_add_handle(multi, curl);
  }
  (*left)++;
}

int main(void)
{
  CURLM *multi;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  multi = curl_multi_init();
  if(multi) {
    CURLMsg *msg;
    unsigned int transfers = 0;
    int msgs_left = -1;
    int left = 0;

    /* Limit the amount of simultaneous connections curl should allow: */
    curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

    for(transfers = 0; transfers < MAX_PARALLEL && transfers < NUM_URLS;
        transfers++)
      add_transfer(multi, transfers, &left);

    do {
      int still_alive = 1;
      curl_multi_perform(multi, &still_alive);

      /* !checksrc! disable EQUALSNULL 1 */
      while((msg = curl_multi_info_read(multi, &msgs_left)) != NULL) {
        if(msg->msg == CURLMSG_DONE) {
          const char *url;
          CURL *curl = msg->easy_handle;
          curl_easy_getinfo(curl, CURLINFO_PRIVATE, &url);
          fprintf(stderr, "R: %d - %s <%s>\n",
                  msg->data.result, curl_easy_strerror(msg->data.result), url);
          curl_multi_remove_handle(multi, curl);
          curl_easy_cleanup(curl);
          left--;
        }
        else {
          fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
        }
        if(transfers < NUM_URLS)
          add_transfer(multi, transfers++, &left);
      }
      if(left)
        curl_multi_wait(multi, NULL, 0, 1000, NULL);

    } while(left);

    curl_multi_cleanup(multi);
  }
  curl_global_cleanup();

  return EXIT_SUCCESS;
}
