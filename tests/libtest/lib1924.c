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

/*
 * A transfer queued by CURLMOPT_MAX_TOTAL_CONNECTIONS for longer than its
 * connect timeout must fail with CURLE_OPERATION_TIMEDOUT, also when no
 * overall timeout is set.
 *
 * The first transfer pauses in its write callback and keeps the only
 * allowed connection busy. The second one is queued (PENDING) and has a
 * short connect timeout.
 */

static size_t t1924_write_pause(char *ptr, size_t size, size_t nmemb,
                                void *userp)
{
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return CURL_WRITEFUNC_PAUSE;
}

static CURLcode test_lib1924(const char *URL)
{
  CURL *busy = NULL;
  CURL *queued = NULL;
  CURLM *multi = NULL;
  CURLcode result = TEST_ERR_FAILURE;
  int running;
  int loops;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(busy);
  easy_setopt(busy, CURLOPT_URL, URL);
  easy_setopt(busy, CURLOPT_WRITEFUNCTION, t1924_write_pause);

  easy_init(queued);
  easy_setopt(queued, CURLOPT_URL, URL);
  easy_setopt(queued, CURLOPT_VERBOSE, 1L);
  easy_setopt(queued, CURLOPT_CONNECTTIMEOUT_MS, 200L);

  multi_init(multi);
  multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1L);

  multi_add_handle(multi, busy);
  multi_add_handle(multi, queued);

  /* the paused transfer never ends, give the queued one 5 seconds */
  for(loops = 0; loops < 50; loops++) {
    CURLMsg *msg;
    int msgs;
    int num;

    multi_perform(multi, &running);
    abort_on_test_timeout();

    for(;;) {
      msg = curl_multi_info_read(multi, &msgs);
      if(!msg)
        break;
      if(msg->msg == CURLMSG_DONE && msg->easy_handle == queued) {
        curl_mprintf("queued transfer done: %d\n", (int)msg->data.result);
        result = msg->data.result == CURLE_OPERATION_TIMEDOUT ?
                 CURLE_OK : TEST_ERR_FAILURE;
        goto test_cleanup;
      }
    }

    multi_poll(multi, NULL, 0, 100, &num);
    abort_on_test_timeout();
  }

  curl_mprintf("queued transfer did not time out\n");

test_cleanup:

  /* proper cleanup sequence - type PA */
  curl_multi_remove_handle(multi, queued);
  curl_multi_remove_handle(multi, busy);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(queued);
  curl_easy_cleanup(busy);
  curl_global_cleanup();

  return result;
}
