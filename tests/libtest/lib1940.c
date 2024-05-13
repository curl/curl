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

static const char *show[]={
  "daTE",
  "Server",
  "content-type",
  "content-length",
  "location",
  "set-cookie",
  "silly-thing",
  "fold",
  "blank",
  "Blank2",
  NULL
};

#ifdef LIB1946
#define HEADER_REQUEST 0
#else
#define HEADER_REQUEST -1
#endif

static void showem(CURL *easy, unsigned int type)
{
  int i;
  struct curl_header *header;
  for(i = 0; show[i]; i++) {
    if(CURLHE_OK == curl_easy_header(easy, show[i], 0, type, HEADER_REQUEST,
                                     &header)) {
      if(header->amount > 1) {
        /* more than one, iterate over them */
        size_t index = 0;
        size_t amount = header->amount;
        do {
          printf("- %s == %s (%u/%u)\n", header->name, header->value,
                 (int)index, (int)amount);

          if(++index == amount)
            break;
          if(CURLHE_OK != curl_easy_header(easy, show[i], index, type,
                                           HEADER_REQUEST, &header))
            break;
        } while(1);
      }
      else {
        /* only one of this */
        printf(" %s == %s\n", header->name, header->value);
      }
    }
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
  CURL *easy = NULL;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_DEFAULT);
  easy_init(easy);
  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
  /* ignores any content */
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);

  /* if there's a proxy set, use it */
  if(libtest_arg2 && *libtest_arg2) {
    easy_setopt(easy, CURLOPT_PROXY, libtest_arg2);
    easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
  }
  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

  showem(easy, CURLH_HEADER);
  if(libtest_arg2 && *libtest_arg2) {
    /* now show connect headers only */
    showem(easy, CURLH_CONNECT);
  }
  showem(easy, CURLH_1XX);
  showem(easy, CURLH_TRAILER);

test_cleanup:
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return res;
}
