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
/* <DESC>
 * WebSockets pingpong
 * </DESC>
 */
/* curl stuff */
#include "curl_setup.h"
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

#ifndef CURL_DISABLE_WEBSOCKETS

static CURLcode ping(CURL *curl, const char *send_payload)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, send_payload, strlen(send_payload), &sent, 0,
                 CURLWS_PING);
  fprintf(stderr,
          "ws: curl_ws_send returned %u, sent %u\n", (int)result, (int)sent);

  return result;
}

static CURLcode recv_pong(CURL *curl, const char *expected_payload)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  char buffer[256];
  CURLcode result = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
  if(result) {
    fprintf(stderr, "ws: curl_ws_recv returned %u, received %ld\n",
            (int)result, (long)rlen);
    return result;
  }

  if(!(meta->flags & CURLWS_PONG)) {
    fprintf(stderr, "recv_pong: wrong frame, got %d bytes rflags %x\n",
            (int)rlen, meta->flags);
    return CURLE_RECV_ERROR;
  }

  fprintf(stderr, "ws: got PONG back\n");
  if(rlen == strlen(expected_payload) &&
     !memcmp(expected_payload, buffer, rlen)) {
    fprintf(stderr, "ws: got the same payload back\n");
    return CURLE_OK;
  }
  fprintf(stderr, "ws: did NOT get the same payload back\n");
  return CURLE_RECV_ERROR;
}

/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
  fprintf(stderr,
          "ws: curl_ws_send returned %u, sent %u\n", (int)result, (int)sent);
}

#if defined(__TANDEM)
# include <cextdecs.h(PROCESS_DELAY_)>
#endif
static CURLcode pingpong(CURL *curl, const char *payload)
{
  CURLcode res;
  int i;

  res = ping(curl, payload);
  if(res)
    return res;
  for(i = 0; i < 10; ++i) {
    fprintf(stderr, "Receive pong\n");
    res = recv_pong(curl, payload);
    if(res == CURLE_AGAIN) {
#ifdef _WIN32
      Sleep(100);
#elif defined(__TANDEM)
      /* NonStop only defines usleep when building for a threading model */
# if defined(_PUT_MODEL_) || defined(_KLT_MODEL_)
      usleep(100*1000);
# else
      PROCESS_DELAY_(100*1000);
# endif
#else
      usleep(100*1000);
#endif
      continue;
    }
    websocket_close(curl);
    return res;
  }
  websocket_close(curl);
  return CURLE_RECV_ERROR;
}

#endif

int main(int argc, char *argv[])
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURL *curl;
  CURLcode res = CURLE_OK;
  const char *url, *payload;

  if(argc != 3) {
    fprintf(stderr, "usage: ws-pingpong url payload\n");
    return 2;
  }
  url = argv[1];
  payload = argv[2];

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ws-pingpong");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %u\n", (int)res);
    if(res == CURLE_OK)
      res = pingpong(curl, payload);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)res;

#else /* !CURL_DISABLE_WEBSOCKETS */
  (void)argc;
  (void)argv;
  fprintf(stderr, "WebSockets not enabled in libcurl\n");
  return 1;
#endif /* CURL_DISABLE_WEBSOCKETS */
}
