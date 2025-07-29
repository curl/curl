/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

static CURLcode test_lib1510(const char *URL)
{
  static const int NUM_URLS = 4;

  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  int i;
  char target_url[256];
  char dnsentry[256];
  struct curl_slist *slist = NULL, *slist2;
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;

  (void)URL;

  /* Create fake DNS entries for serverX.example.com for all handles */
  for(i = 0; i < NUM_URLS; i++) {
    curl_msnprintf(dnsentry, sizeof(dnsentry),
                   "server%d.example.com:%s:%s", i + 1, port, address);
    curl_mprintf("%s\n", dnsentry);
    slist2 = curl_slist_append(slist, dnsentry);
    if(!slist2) {
      curl_mfprintf(stderr, "curl_slist_append() failed\n");
      goto test_cleanup;
    }
    slist = slist2;
  }

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  /* get an easy handle */
  easy_init(curl);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  /* include headers */
  easy_setopt(curl, CURLOPT_HEADER, 1L);

  easy_setopt(curl, CURLOPT_RESOLVE, slist);

  easy_setopt(curl, CURLOPT_MAXCONNECTS, 3L);

  /* get NUM_URLS easy handles */
  for(i = 0; i < NUM_URLS; i++) {
    /* specify target */
    curl_msnprintf(target_url, sizeof(target_url),
                   "http://server%d.example.com:%s/path/1510%04i",
                   i + 1, port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(curl, CURLOPT_URL, target_url);

    res = curl_easy_perform(curl);
    if(res)
      goto test_cleanup;

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_easy_cleanup(curl);

  curl_slist_free_all(slist);

  curl_global_cleanup();

  return res;
}
