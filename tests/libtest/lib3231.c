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

static CURLcode connect_only_complete(CURLM *multi, CURL *easy)
{
  CURLcode result = CURLE_OK;
  CURLMsg *msg;
  int running;
  int msgs_left;
  int numfds;

  do {
    multi_perform(multi, &running);
    abort_on_test_timeout();
    if(running)
      multi_poll(multi, NULL, 0, 1000, &numfds);
  } while(running);

  msg = curl_multi_info_read(multi, &msgs_left);
  if(!msg || msg->msg != CURLMSG_DONE || msg->easy_handle != easy ||
     msg->data.result != CURLE_OK || msgs_left) {
    curl_mfprintf(stderr, "Unexpected transfer completion\n");
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  return result;
}

static CURLcode test_lib3231(const char *URL)
{
  CURL *connect_only = NULL;
  CURL *http = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_off_t pending;
  int running;

  start_test_timing();
  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);
  if(testnum == 3232)
    multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 1L);
  else
    multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);

  easy_init(connect_only);
  easy_setopt(connect_only, CURLOPT_URL, URL);
  easy_setopt(connect_only, CURLOPT_CONNECT_ONLY, 1L);
  easy_setopt(connect_only, CURLOPT_VERBOSE, 1L);
  multi_add_handle(multi, connect_only);

  result = connect_only_complete(multi, connect_only);
  if(result)
    goto test_cleanup;

  result = curl_easy_getinfo(connect_only, CURLINFO_ACTIVESOCKET, &sock);
  if(result)
    goto test_cleanup;
  if(sock == CURL_SOCKET_BAD) {
    curl_mfprintf(stderr, "CONNECT_ONLY did not retain its socket\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* Do not send or receive on connect_only before competing for its slot:
     the completed transfer has detached, but the application still owns it. */
  easy_init(http);
  easy_setopt(http, CURLOPT_URL, URL);
  easy_setopt(http, CURLOPT_VERBOSE, 1L);
  multi_add_handle(multi, http);
  multi_perform(multi, &running);

  result = curl_easy_getinfo(connect_only, CURLINFO_ACTIVESOCKET, &sock);
  if(result)
    goto test_cleanup;
  if(sock == CURL_SOCKET_BAD) {
    curl_mfprintf(stderr,
                  "Connection limit evicted the CONNECT_ONLY socket\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(curl_multi_get_offt(multi, CURLMINFO_XFERS_PENDING, &pending) ||
     pending != 1) {
    curl_mfprintf(stderr,
                  "HTTP transfer did not wait for a connection slot\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* Releasing the application-owned connection must let HTTP proceed. */
  multi_remove_handle(multi, connect_only);
  curl_easy_cleanup(connect_only);
  connect_only = NULL;
  result = connect_only_complete(multi, http);

test_cleanup:
  if(multi && connect_only)
    curl_multi_remove_handle(multi, connect_only);
  if(multi && http)
    curl_multi_remove_handle(multi, http);
  curl_easy_cleanup(connect_only);
  curl_easy_cleanup(http);
  curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
}
