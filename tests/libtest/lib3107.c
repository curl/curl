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

static int t3107_notified;
static CURLMcode t3107_mres;
static CURLcode t3107_eres;

static void t3107_notify_cb(CURLM *multi, unsigned int notification,
                            CURL *easy, void *user_data)
{
  (void)user_data;
  if(notification != CURLMNOTIFY_INFO_READ)
    return;
  t3107_notified++;
  t3107_mres = curl_multi_remove_handle(multi, easy);
  t3107_eres = curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_cleanup(easy);
}

static CURLcode test_lib3107(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  CURLMsg *msg;
  int running = 1;
  int queued;

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);
  multi_setopt(multi, CURLMOPT_NOTIFYFUNCTION, t3107_notify_cb);

  if(curl_multi_notify_enable(multi, CURLMNOTIFY_INFO_READ) != CURLM_OK) {
    curl_mfprintf(stderr, "curl_multi_notify_enable() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);

  multi_add_handle(multi, curl);

  while(running) {
    CURLMcode mres = curl_multi_perform(multi, &running);
    if(!mres && running)
      mres = curl_multi_poll(multi, NULL, 0, 1000, NULL);
    if(mres) {
      curl_mfprintf(stderr, "curl_multi failed, with code %d (%s)\n",
                    (int)mres, curl_multi_strerror(mres));
      result = TEST_ERR_MULTI;
      goto test_cleanup;
    }
  }

  do {
    msg = curl_multi_info_read(multi, &queued);
  } while(msg);

  if(!t3107_notified) {
    curl_mfprintf(stderr, "no CURLMNOTIFY_INFO_READ notification\n");
    result = TEST_ERR_MAJOR_BAD;
  }
  else if(t3107_mres != CURLM_BAD_EASY_HANDLE) {
    curl_mfprintf(stderr, "curl_multi_remove_handle() returned %d\n",
                  (int)t3107_mres);
    result = TEST_ERR_MAJOR_BAD;
  }
  else if(t3107_eres != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "curl_easy_setopt() returned %d\n",
                  (int)t3107_eres);
    result = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:
  curl_multi_remove_handle(multi, curl);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
