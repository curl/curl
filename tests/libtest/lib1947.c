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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "test.h"

#include "memdebug.h"

static size_t writecb(char *data, size_t n, size_t l, void *userp)
{
  /* ignore the data */
  (void)data;
  (void)userp;
  return n*l;
}
int test(char *URL)
{
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    struct curl_header *h;
    int count = 0;
    int origins;

    /* perform a request that involves redirection */
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecb);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    res = curl_easy_perform(curl);
    if(res)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* count the number of requests by reading the first header of each
       request. */
    origins = (CURLH_HEADER|CURLH_TRAILER|CURLH_CONNECT|
               CURLH_1XX|CURLH_PSEUDO);
    do {
      h = curl_easy_nextheader(curl, origins, count, NULL);
      if(h)
        count++;
    } while(h);
    printf("count = %u\n", count);

    /* perform another request - without redirect */
    curl_easy_setopt(curl, CURLOPT_URL, libtest_arg2);
    res = curl_easy_perform(curl);
    if(res)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* count the number of requests again. */
    count = 0;
    do {
      h = curl_easy_nextheader(curl, origins, count, NULL);
      if(h)
        count++;
    } while(h);
    printf("count = %u\n", count);
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return 0;
}
