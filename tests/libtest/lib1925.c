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
 * A WebSocket Upgrade is still connecting while in the PERFORMING state.
 * With receiving paused before the Upgrade response is read, the connect
 * timeout must still fail the transfer, also when no overall timeout is
 * set.
 */
#ifndef CURL_DISABLE_WEBSOCKETS
static int t1925_debug(CURL *curl, curl_infotype type, char *data,
                       size_t size, void *userp)
{
  (void)curl;
  (void)data;
  (void)size;
  if(type == CURLINFO_HEADER_OUT)
    *(int *)userp = 1; /* the Upgrade request is out */
  return 0;
}
#endif

static CURLcode test_lib1925(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = TEST_ERR_FAILURE;
  int running;
  int loops;
  int sent = 0;
  int paused = 0;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, t1925_debug);
  easy_setopt(curl, CURLOPT_DEBUGDATA, &sent);
  easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 200L);

  multi_init(multi);
  multi_add_handle(multi, curl);

  /* give the connect timeout 5 seconds to trigger */
  for(loops = 0; loops < 50; loops++) {
    CURLMsg *msg;
    int msgs;
    int num;

    multi_perform(multi, &running);
    abort_on_test_timeout();

    if(sent && !paused) {
      /* the server never responds, stop reading */
      curl_easy_pause(curl, CURLPAUSE_RECV);
      paused = 1;
    }

    msg = curl_multi_info_read(multi, &msgs);
    if(msg && msg->msg == CURLMSG_DONE) {
      curl_mprintf("transfer done: %d\n", (int)msg->data.result);
      result = msg->data.result == CURLE_OPERATION_TIMEDOUT ?
               CURLE_OK : TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    multi_poll(multi, NULL, 0, 100, &num);
    abort_on_test_timeout();
  }

  curl_mprintf("transfer did not time out\n");

test_cleanup:

  /* proper cleanup sequence - type PA */
  curl_multi_remove_handle(multi, curl);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
#else
  (void)URL;
  curl_mfprintf(stderr, "Missing support\n");
  return CURLE_UNSUPPORTED_PROTOCOL;
#endif
}
