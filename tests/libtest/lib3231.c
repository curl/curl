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

static CURLcode test_lib3231(const char *URL)
{
  CURL *easy_a = NULL;
  CURL *easy_b = NULL;
  CURLSH *share = NULL;
  CURLSHcode shresult;
  CURLcode result = CURLE_OK;
  curl_socket_t socket_a = CURL_SOCKET_BAD;
  curl_socket_t socket_b = CURL_SOCKET_BAD;
  curl_socket_t socket_after = CURL_SOCKET_BAD;
  curl_off_t conn_id = -1;
  size_t sent = 0;

  global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  if(!share) {
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  shresult = curl_share_setopt(share, CURLSHOPT_SHARE,
                               CURL_LOCK_DATA_CONNECT);
  if(shresult != CURLSHE_OK) {
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  easy_init(easy_a);
  easy_setopt(easy_a, CURLOPT_URL, URL);
  easy_setopt(easy_a, CURLOPT_CONNECT_ONLY, 1L);
  result = curl_easy_perform(easy_a);
  if(result)
    goto test_cleanup;
  result = curl_easy_getinfo(easy_a, CURLINFO_ACTIVESOCKET, &socket_a);
  if(result)
    goto test_cleanup;

  easy_init(easy_b);
  easy_setopt(easy_b, CURLOPT_SHARE, share);
  easy_setopt(easy_b, CURLOPT_URL, URL);
  easy_setopt(easy_b, CURLOPT_CONNECT_ONLY, 1L);
  result = curl_easy_perform(easy_b);
  if(result)
    goto test_cleanup;
  result = curl_easy_getinfo(easy_b, CURLINFO_ACTIVESOCKET, &socket_b);
  if(result)
    goto test_cleanup;

  if(socket_a == CURL_SOCKET_BAD || socket_b == CURL_SOCKET_BAD ||
     socket_a == socket_b) {
    curl_mfprintf(stderr, "failed to create two distinct connections\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  easy_setopt(easy_a, CURLOPT_SHARE, share);
  result = curl_easy_getinfo(easy_a, CURLINFO_CONN_ID, &conn_id);
  if(result)
    goto test_cleanup;
  result = curl_easy_getinfo(easy_a, CURLINFO_ACTIVESOCKET, &socket_after);
  if(result)
    goto test_cleanup;

  if(conn_id != -1 || socket_after != CURL_SOCKET_BAD) {
    curl_mfprintf(stderr, "connection survived a connection pool change\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  result = curl_easy_send(easy_a, "x", 1, &sent);
  if(result != CURLE_UNSUPPORTED_PROTOCOL || sent) {
    curl_mfprintf(stderr, "raw send used a connection from the new pool\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  result = CURLE_OK;

test_cleanup:
  curl_easy_cleanup(easy_a);
  curl_easy_cleanup(easy_b);
  curl_share_cleanup(share);
  curl_global_cleanup();
  return result;
}
