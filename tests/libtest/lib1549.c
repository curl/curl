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

#include "testtrace.h"
#include "memdebug.h"

static CURLcode test_lib1549(const char *URL)
{
  CURLcode res;
  CURL *curl;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_COOKIEFILE, "");

  res = curl_easy_perform(curl);

  if(!res) {
    /* extract all known cookies */
    struct curl_slist *cookies = NULL;
    int num = 0;
    res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if(!res && cookies) {
      /* a linked list of cookies in cookie file format */
      struct curl_slist *each = cookies;
      while(each) {
        printf("%s\n", each->data);
        each = each->next;
        num++;
      }
      /* we must free these cookies when we are done */
      curl_slist_free_all(cookies);
    }
    fprintf(stderr, "%d cookies\n", num);
  }
test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
