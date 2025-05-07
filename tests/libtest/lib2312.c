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

#include "test.h"

#ifdef USE_WEBSOCKETS

struct ping_check {
  CURL *curl;
  int pinged;
};

static size_t write_cb(char *b, size_t size, size_t nitems, void *p)
{
  struct ping_check *ping_check = p;
  CURL *curl = ping_check->curl;
  const struct curl_ws_frame *frame = curl_ws_meta(curl);
  size_t sent = 0;
  size_t i = 0;

  /* upon ping, respond with input data, disconnect, mark a success */
  if(frame->flags & CURLWS_PING) {
    curl_mfprintf(stderr, "write_cb received ping with %zd bytes\n",
                  size * nitems);
    curl_mfprintf(stderr, "\n");
    for(i = 0; i < size * nitems; i++) {
      curl_mfprintf(stderr, "%02X%s", (int)b[i],
                    (i % 10 == 0 && i != 0) ? "\n" : " ");
    }
    curl_mfprintf(stderr, "\n");
    curl_mfprintf(stderr, "write_cb sending pong response\n");
    curl_ws_send(curl, b, size * nitems, &sent, 0, CURLWS_PONG);
    curl_mfprintf(stderr, "write_cb closing websocket\n");
    curl_ws_send(curl, NULL, 0, &sent, 0, CURLWS_CLOSE);
    ping_check->pinged = 1;
  }
  else {
    curl_mfprintf(stderr, "ping_check_cb: non-ping message, frame->flags %x\n",
                  frame->flags);
  }

  return size * nitems;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct ping_check state;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    state.curl = curl;
    state.pinged = 0;

    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style, without auto-pong */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "webbie-sox/3");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_WS_OPTIONS, (long)CURLWS_NOAUTOPONG);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);

    res = curl_easy_perform(curl);
    curl_mfprintf(stderr, "curl_easy_perform() returned %u\n", (int)res);

    res = state.pinged ? 0 : 1;

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;
}

#else /* no websockets */
NO_SUPPORT_BUILT_IN
#endif
