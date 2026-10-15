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

static int t3235_closesocket(void *clientp, curl_socket_t sock)
{
  unsigned int *closed = clientp;
  ++*closed;
  return sclose(sock);
}

static CURLcode test_lib3235(const char *URL)
{
  CURL *easy = NULL;
  CURLSH *share = NULL;
  CURLcode result = CURLE_OK;
  unsigned int mode;
  unsigned int closed = 0;

  global_init(CURL_GLOBAL_ALL);

  for(mode = 0; mode < 3; mode++) {
    unsigned int cycle;
    closed = 0;
    share = curl_share_init();
    if(!share) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    if(curl_share_setopt(share, CURLSHOPT_UNSHARE,
                         CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    for(cycle = 0; cycle < 3; cycle++) {
      long connects = -1;
      curl_off_t conn_id = -1;
      curl_socket_t sock = CURL_SOCKET_BAD;
      if(curl_share_setopt(share, CURLSHOPT_SHARE,
                           CURL_LOCK_DATA_CONNECT) != CURLSHE_OK ||
         curl_share_setopt(share, CURLSHOPT_SHARE,
                           CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
        result = TEST_ERR_FAILURE;
        goto test_cleanup;
      }
      easy_init(easy);
      easy_setopt(easy, CURLOPT_SHARE, share);
      easy_setopt(easy, CURLOPT_URL, URL);
      easy_setopt(easy, CURLOPT_CLOSESOCKETFUNCTION, t3235_closesocket);
      easy_setopt(easy, CURLOPT_CLOSESOCKETDATA, &closed);
      result = curl_easy_perform(easy);
      if(result)
        goto test_cleanup;
      result = curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &connects);
      if(result)
        goto test_cleanup;
      if(connects != (cycle ? 0 : 1)) {
        curl_mfprintf(stderr, "shared connection was not reused\n");
        result = TEST_ERR_FAILURE;
        goto test_cleanup;
      }
      if(curl_share_setopt(share, CURLSHOPT_UNSHARE,
                           CURL_LOCK_DATA_CONNECT) != CURLSHE_IN_USE ||
         curl_share_setopt(share, CURLSHOPT_SHARE,
                           CURL_LOCK_DATA_CONNECT) != CURLSHE_IN_USE ||
         curl_share_cleanup(share) != CURLSHE_IN_USE) {
        result = TEST_ERR_FAILURE;
        goto test_cleanup;
      }
      easy_setopt(easy, CURLOPT_SHARE, NULL);
      result = curl_easy_getinfo(easy, CURLINFO_CONN_ID, &conn_id);
      if(result)
        goto test_cleanup;
      result = curl_easy_getinfo(easy, CURLINFO_ACTIVESOCKET, &sock);
      if(result)
        goto test_cleanup;
      if(conn_id != -1 || sock != CURL_SOCKET_BAD) {
        curl_mfprintf(stderr, "connection identifiers survived detaching\n");
        result = TEST_ERR_FAILURE;
        goto test_cleanup;
      }
      curl_easy_cleanup(easy);
      easy = NULL;
      if(mode || cycle < 2) {
        if(curl_share_setopt(share, CURLSHOPT_UNSHARE,
                             CURL_LOCK_DATA_CONNECT) != CURLSHE_OK ||
           curl_share_setopt(share, CURLSHOPT_UNSHARE,
                             CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
          result = TEST_ERR_FAILURE;
          goto test_cleanup;
        }
      }
    }
    if(mode == 2 &&
       curl_share_setopt(share, CURLSHOPT_SHARE,
                         CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    if(closed) {
      curl_mfprintf(stderr, "connection closed before share cleanup\n");
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    if(curl_share_cleanup(share) != CURLSHE_OK) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    share = NULL;
    if(closed != 1) {
      curl_mfprintf(stderr, "mode %u: expected one close, got %u\n",
                    mode, closed);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
  }

test_cleanup:
  curl_easy_cleanup(easy);
  curl_share_cleanup(share);
  curl_global_cleanup();
  return result;
}
