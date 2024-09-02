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
#if 0

static CURLcode ping(CURL *curl, const char *send_payload)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, send_payload, strlen(send_payload), &sent, CURLWS_PING);
  fprintf(stderr,
          "ws: curl_ws_send returned %d, sent %d\n", result, (int)sent);

  return result;
}

static CURLcode recv_pong(CURL *curl, const char *expected_payload)
{
  size_t rlen;
  unsigned int rflags;
  char buffer[256];
  CURLcode result =
    curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &rflags);
  if(rflags & CURLWS_PONG) {
    int same = 0;
    fprintf(stderr, "ws: got PONG back\n");
    if(rlen == strlen(expected_payload)) {
      if(!memcmp(expected_payload, buffer, rlen)) {
        fprintf(stderr, "ws: got the same payload back\n");
        same = 1;
      }
    }
    if(!same)
      fprintf(stderr, "ws: did NOT get the same payload back\n");
  }
  else {
    fprintf(stderr, "recv_pong: got %d bytes rflags %x\n", (int)rlen, rflags);
  }
  fprintf(stderr, "ws: curl_ws_recv returned %d, received %d\n", result,
          (int)rlen);
  return result;
}

/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, CURLWS_CLOSE);
  fprintf(stderr,
          "ws: curl_ws_send returned %d, sent %d\n", result, (int)sent);
}

static void websocket(CURL *curl)
{
  int i = 0;
  fprintf(stderr, "ws: websocket() starts\n");
  do {
    if(ping(curl, "foobar"))
      return;
    if(recv_pong(curl, "foobar"))
      return;
    sleep(2);
  } while(i++ < 10);
  websocket_close(curl);
}

#endif

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  CURL *easy = p;
  unsigned char *buffer = (unsigned char *)b;
  size_t i;
  size_t sent;
  unsigned char pong[] = {
    0x8a, 0x0
  };
  size_t incoming = nitems;
  fprintf(stderr, "Called CURLOPT_WRITEFUNCTION with %d bytes: ",
          (int)nitems);
  for(i = 0; i < nitems; i++)
    fprintf(stderr, "%02x ", (unsigned char)buffer[i]);
  fprintf(stderr, "\n");
  (void)size;
  if(buffer[0] == 0x89) {
    CURLcode result;
    fprintf(stderr, "send back a simple PONG\n");
    result = curl_ws_send(easy, pong, 2, &sent, 0, 0);
    if(result)
      nitems = 0;
  }
  if(nitems != incoming)
    fprintf(stderr, "returns error from callback\n");
  return nitems;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "webbie-sox/3");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_WS_OPTIONS, CURLWS_RAW_MODE);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl);
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %d\n", res);
#if 0
    if(res == CURLE_OK)
      websocket(curl);
#endif
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;
}

#else /* no WebSockets */
NO_SUPPORT_BUILT_IN
#endif
