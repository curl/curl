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
 * The connect timeout must not fail a connection that completed while the
 * application was not calling curl_multi_perform(): issue the connect, stay
 * away for longer than CURLOPT_CONNECTTIMEOUT_MS, then drive the transfer
 * to completion.
 *
 * The address is put in the DNS cache up front (CURLOPT_RESOLVE) so that no
 * resolving happens inside the connect budget (macOS resolves even IP
 * literals, USE_RESOLVE_ON_IPS), and CURLOPT_NOSIGNAL is set so that the
 * synchronous resolver does not reject the sub-second timeout for its
 * alarm() based limit before it even looks at the cache.
 */
static CURLcode test_lib590(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  struct curl_slist *resolve = NULL;
  CURLMsg *msg;
  char entry[256];
  int running;
  int msgs;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  /* libtest_arg2 = host, libtest_arg3 = port */
  curl_msnprintf(entry, sizeof(entry), "%s:%s:%s",
                 libtest_arg2, libtest_arg3, libtest_arg2);
  resolve = curl_slist_append(NULL, entry);
  if(!resolve) {
    curl_mfprintf(stderr, "curl_slist_append() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_RESOLVE, resolve);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 200L);
  easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);

  multi_init(multi);

  multi_add_handle(multi, curl);

  /* this issues the connect() */
  multi_perform(multi, &running);
  abort_on_test_timeout();

  /* the application is busy for longer than the connect timeout */
  curlx_wait_ms(600);

  while(running) {
    int num;
    multi_perform(multi, &running);
    abort_on_test_timeout();
    if(running) {
      CURLMcode mresult = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT,
                                          &num);
      if(mresult != CURLM_OK) {
        curl_mprintf("curl_multi_wait() returned %d\n", mresult);
        result = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      abort_on_test_timeout();
    }
  }

  msg = curl_multi_info_read(multi, &msgs);
  if(msg && msg->msg == CURLMSG_DONE)
    result = msg->data.result;
  else
    result = TEST_ERR_FAILURE;

test_cleanup:

  /* proper cleanup sequence - type PA */
  curl_multi_remove_handle(multi, curl);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_slist_free_all(resolve);
  curl_global_cleanup();

  return result;
}
