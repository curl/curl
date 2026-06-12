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

static CURLcode test_lib1905(const char *URL)
{
  CURLSH *share = NULL;
  CURL *curl = NULL;
  int unfinished;
  CURLM *multi;

  curl_global_init(CURL_GLOBAL_ALL);

  multi = curl_multi_init();
  if(!multi) {
    curl_global_cleanup();
    return TEST_ERR_MULTI;
  }
  share = curl_share_init();
  if(!share)
    goto cleanup;

  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);

  curl = curl_easy_init();
  if(!curl)
    goto cleanup;

  curl_easy_setopt(curl, CURLOPT_SHARE, share);
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, libtest_arg2);
  curl_easy_setopt(curl, CURLOPT_COOKIEJAR, libtest_arg2);

  curl_multi_add_handle(multi, curl);

  unfinished = 1;
  while(unfinished) {
    int MAX = 0;
    long max_tout;
    fd_set R, W, E;
    struct timeval timeout;

    FD_ZERO(&R);
    FD_ZERO(&W);
    FD_ZERO(&E);
    curl_multi_perform(multi, &unfinished);

    curl_multi_fdset(multi, &R, &W, &E, &MAX);
    curl_multi_timeout(multi, &max_tout);

    if(max_tout > 0) {
      curlx_mstotv(&timeout, max_tout);
    }
    else {
      timeout.tv_sec = 0;
      timeout.tv_usec = 1000;
    }

    select(MAX + 1, &R, &W, &E, &timeout);
  }

  curl_easy_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");
  curl_easy_setopt(curl, CURLOPT_SHARE, NULL);

  curl_multi_remove_handle(multi, curl);
cleanup:
  curl_easy_cleanup(curl);
  curl_share_cleanup(share);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return CURLE_OK;
}
