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
/*
 * This source code is used for lib1502, lib1503, lib1504 and lib1505 with
 * only the testnum controlling the cleanup sequence.
 *
 * Test case 1502 converted from bug report #3575448, identifying a memory
 * leak in the CURLOPT_RESOLVE handling with the multi interface.
 */

#include "first.h"

static CURLcode test_lib1502(const char *URL)
{
  CURL *curl = NULL;
  CURL *curldupe;
  CURLM *multi = NULL;
  int still_running;
  CURLcode result = CURLE_OK;
  char redirect[160];

  /* DNS cache injection */
  struct curl_slist *dns_cache_list;

  res_global_init(CURL_GLOBAL_ALL);
  if(result) {
    return result;
  }

  curl_msnprintf(redirect, sizeof(redirect), "google.com:%s:%s", libtest_arg2,
                 libtest_arg3);

  start_test_timing();

  dns_cache_list = curl_slist_append(NULL, redirect);
  if(!dns_cache_list) {
    curl_mfprintf(stderr, "curl_slist_append() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_RESOLVE, dns_cache_list);

  curldupe = curl_easy_duphandle(curl);
  if(curldupe) {
    curl_easy_cleanup(curl);
    curl = curldupe;
  }
  else {
    curl_slist_free_all(dns_cache_list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }

  multi_init(multi);

  multi_add_handle(multi, curl);

  multi_perform(multi, &still_running);

  abort_on_test_timeout();

  while(still_running) {
    struct timeval timeout;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -99;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    abort_on_test_timeout();

    multi_perform(multi, &still_running);

    abort_on_test_timeout();
  }

test_cleanup:

  switch(testnum) {
  case 1502:
  default:
    /* undocumented cleanup sequence - type UA */
    curl_multi_cleanup(multi);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    break;
  case 1503:
    /* proper cleanup sequence - type PA */
    curl_multi_remove_handle(multi, curl);
    curl_multi_cleanup(multi);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    break;
  case 1504:
    /* undocumented cleanup sequence - type UB */
    curl_easy_cleanup(curl);
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    break;
  case 1505:
    /* proper cleanup sequence - type PB */
    curl_multi_remove_handle(multi, curl);
    curl_easy_cleanup(curl);
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    break;
  }

  curl_slist_free_all(dns_cache_list);

  return result;
}
