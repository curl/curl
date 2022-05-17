/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Extract headers post transfer with the header API
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}

int main(void)
{
  CURL *curl;

  curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_header *header;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    /* example.com is redirected, so we tell libcurl to follow redirection */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* this example just ignores the content */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    if(CURLHE_OK == curl_easy_header(curl, "Content-Type", 0, CURLH_HEADER,
                                     -1, &header))
      printf("Got content-type: %s\n", header->value);

    printf("All server headers:\n");
    {
      struct curl_header *h;
      struct curl_header *prev = NULL;
      do {
        h = curl_easy_nextheader(curl, CURLH_HEADER, -1, prev);
        if(h)
          printf(" %s: %s (%u)\n", h->name, h->value, (int)h->amount);
        prev = h;
      } while(h);

    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
