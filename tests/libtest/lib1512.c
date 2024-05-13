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

/*
 * Use global DNS cache (while deprecated it should still work), populate it
 * with CURLOPT_RESOLVE in the first request and then make sure a subsequent
 * easy transfer finds and uses the populated stuff.
 */

#include "test.h"

#include "memdebug.h"

#define NUM_HANDLES 2

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl[NUM_HANDLES] = {NULL, NULL};
  char *port = libtest_arg3;
  char *address = libtest_arg2;
  char dnsentry[256];
  struct curl_slist *slist = NULL;
  int i;
  char target_url[256];
  (void)URL; /* URL is setup in the code */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  msnprintf(dnsentry, sizeof(dnsentry), "server.example.curl:%s:%s",
            port, address);
  printf("%s\n", dnsentry);
  slist = curl_slist_append(slist, dnsentry);

  /* get NUM_HANDLES easy handles */
  for(i = 0; i < NUM_HANDLES; i++) {
    /* get an easy handle */
    easy_init(curl[i]);
    /* specify target */
    msnprintf(target_url, sizeof(target_url),
              "http://server.example.curl:%s/path/1512%04i",
              port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(curl[i], CURLOPT_URL, target_url);
    /* go verbose */
    easy_setopt(curl[i], CURLOPT_VERBOSE, 1L);
    /* include headers */
    easy_setopt(curl[i], CURLOPT_HEADER, 1L);

    CURL_IGNORE_DEPRECATION(
      easy_setopt(curl[i], CURLOPT_DNS_USE_GLOBAL_CACHE, 1L);
    )
  }

  /* make the first one populate the GLOBAL cache */
  easy_setopt(curl[0], CURLOPT_RESOLVE, slist);

  /* run NUM_HANDLES transfers */
  for(i = 0; (i < NUM_HANDLES) && !res; i++) {
    res = curl_easy_perform(curl[i]);
    if(res)
      goto test_cleanup;
  }

test_cleanup:

  curl_easy_cleanup(curl[0]);
  curl_easy_cleanup(curl[1]);
  curl_slist_free_all(slist);
  curl_global_cleanup();

  return res;
}
