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
#include "first.h"

#include "memdebug.h"

static size_t t1940_write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}

static void t1940_showem(CURL *easy, int header_request, unsigned int type)
{
  static const char *testdata[] = {
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

  int i;
  struct curl_header *header;
  for(i = 0; testdata[i]; i++) {
    if(CURLHE_OK == curl_easy_header(easy, testdata[i], 0,
                                     type, header_request, &header)) {
      if(header->amount > 1) {
        /* more than one, iterate over them */
        size_t index = 0;
        size_t amount = header->amount;
        do {
          curl_mprintf("- %s == %s (%zu/%zu)\n", header->name, header->value,
                       index, amount);

          if(++index == amount)
            break;
          if(CURLHE_OK != curl_easy_header(easy, testdata[i], index,
                                           type, header_request, &header))
            break;
        } while(1);
      }
      else {
        /* only one of this */
        curl_mprintf(" %s == %s\n", header->name, header->value);
      }
    }
  }
}

static CURLcode test_lib1940(const char *URL)
{
  CURL *easy = NULL;
  CURLcode res = CURLE_OK;

  int header_request;
  if(testnum == 1946) {
    header_request = 0;
  }
  else {
    header_request = -1;
  }

  global_init(CURL_GLOBAL_DEFAULT);
  easy_init(easy);
  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
  /* ignores any content */
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, t1940_write_cb);

  /* if there's a proxy set, use it */
  if(libtest_arg2 && *libtest_arg2) {
    easy_setopt(easy, CURLOPT_PROXY, libtest_arg2);
    easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
  }
  res = curl_easy_perform(easy);
  if(res)
    goto test_cleanup;

  t1940_showem(easy, header_request, CURLH_HEADER);
  if(libtest_arg2 && *libtest_arg2) {
    /* now show connect headers only */
    t1940_showem(easy, header_request, CURLH_CONNECT);
  }
  t1940_showem(easy, header_request, CURLH_1XX);
  t1940_showem(easy, header_request, CURLH_TRAILER);

test_cleanup:
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return res;
}
