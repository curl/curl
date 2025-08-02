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

#ifndef CURL_DISABLE_WEBSOCKETS
static CURLcode recv_any(CURL *curl)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  char buffer[256];
  CURLcode result = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
  if(result)
    return result;

  curl_mfprintf(stderr, "recv_any: got %zu bytes rflags %x\n", rlen,
                meta->flags);
  return CURLE_OK;
}

static void t2304_websocket(CURL *curl)
{
  int i = 0;
  curl_mfprintf(stderr, "ws: websocket() starts\n");
  do {
    recv_any(curl);
    curl_mfprintf(stderr, "Send ping\n");
    if(ws_send_ping(curl, "foobar"))
      return;
    curl_mfprintf(stderr, "Receive pong\n");
    if(ws_recv_pong(curl, "foobar")) {
      curl_mprintf("Connection closed\n");
      return;
    }
    curlx_wait_ms(2000);
  } while(i++ < 10);
  ws_close(curl);
}
#endif

static CURLcode test_lib2304(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "websocket/2304");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    curl_mfprintf(stderr, "curl_easy_perform() returned %d\n", res);
    if(res == CURLE_OK)
      t2304_websocket(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;
#else
  NO_SUPPORT_BUILT_IN
#endif
}
