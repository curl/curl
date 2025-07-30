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

#include "testtrace.h"
#include "memdebug.h"

#ifndef CURL_DISABLE_WEBSOCKETS

static CURLcode pingpong(CURL *curl, const char *payload)
{
  CURLcode res;
  int i;

  res = ws_send_ping(curl, payload);
  if(res)
    return res;
  for(i = 0; i < 10; ++i) {
    curl_mfprintf(stderr, "Receive pong\n");
    res = ws_recv_pong(curl, payload);
    if(res == CURLE_AGAIN) {
      curlx_wait_ms(100);
      continue;
    }
    ws_close(curl);
    return res;
  }
  ws_close(curl);
  return CURLE_RECV_ERROR;
}

#endif

static CURLcode test_cli_ws_pingpong(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURL *curl;
  CURLcode res = CURLE_OK;
  const char *payload;

  if(!URL || !libtest_arg2) {
    curl_mfprintf(stderr, "need args: URL payload\n");
    return (CURLcode)2;
  }
  payload = libtest_arg2;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ws-pingpong");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    curl_mfprintf(stderr, "curl_easy_perform() returned %u\n", res);
    if(res == CURLE_OK)
      res = pingpong(curl, payload);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;

#else /* !CURL_DISABLE_WEBSOCKETS */
  (void)URL;
  curl_mfprintf(stderr, "WebSockets not enabled in libcurl\n");
  return (CURLcode)1;
#endif /* CURL_DISABLE_WEBSOCKETS */
}
