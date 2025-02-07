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

static void showem(CURL *easy, unsigned int type)
{
  struct curl_header *header = NULL;
  struct curl_header *prev = NULL;

  /* !checksrc! disable EQUALSNULL 1 */
  while((header = curl_easy_nextheader(easy, type, 0, prev)) != NULL) {
    printf(" %s == %s (%u/%u)\n", header->name, header->value,
           (int)header->index, (int)header->amount);
    prev = header;
  }
}

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}
CURLcode test(char *URL)
{
  CURL *easy;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_DEFAULT);

  easy_init(easy);
  curl_easy_setopt(easy, CURLOPT_URL, URL);
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
  /* ignores any content */
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);

  /* if there's a proxy set, use it */
  if(libtest_arg2 && *libtest_arg2) {
    curl_easy_setopt(easy, CURLOPT_PROXY, libtest_arg2);
    curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
  }
  res = curl_easy_perform(easy);
  if(res) {
    printf("badness: %d\n", res);
  }
  showem(easy, CURLH_CONNECT|CURLH_HEADER|CURLH_TRAILER|CURLH_1XX);

test_cleanup:
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return res;
}
