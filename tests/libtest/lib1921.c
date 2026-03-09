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

static size_t write1921(void *ptr, size_t size, size_t nmemb, void *data)
{
  bool *data_received = (bool *)data;
  (void)ptr;
  *data_received = true;
  return size * nmemb;
}

static CURLcode test_lib1921(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURLSH *share;
  CURL *easy;
  bool data_received = false;
  CURLM *multi;

  curl_global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

  easy = curl_easy_init();

  curl_easy_setopt(easy, CURLOPT_SHARE, share);

  /* The URL should be for a long enough download, so the transfer is not
     completed when the first data chunk is delivered to the write function. */
  curl_easy_setopt(easy, CURLOPT_URL, URL);

  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write1921);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, (void *)&data_received);

  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  multi = curl_multi_init();

  curl_multi_add_handle(multi, easy);

  for(;;) {
    int still_running = 0;

    CURLMcode mresult = curl_multi_perform(multi, &still_running);
    if(mresult != CURLM_OK) {
      curl_mprintf("curl_multi_perform() failed, code %d.\n",
                   (int)mresult);
      break;
    }

    if(!still_running || data_received) {
      break; /* Break when first data chunk is received or transfer is done. */
    }

    /* wait for activity, timeout or "nothing" */
    mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);
    if(mresult != CURLM_OK) {
      curl_mprintf("curl_multi_poll() failed, code %d.\n", (int)mresult);
      break;
    }
  } /* if there are still transfers, loop */

    /* Set a null share first. */
  curl_easy_setopt(easy, CURLOPT_SHARE, NULL);

  /* Remove the easy handle after clearing the share. !!! Crash!!! */
  curl_multi_remove_handle(multi, easy);

  curl_multi_cleanup(multi);
  curl_share_cleanup(share);

  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return result;
}
