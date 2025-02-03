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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "test.h"

#ifndef FETCH_DISABLE_WEBSOCKETS

static FETCHcode send_ping(FETCH *fetch, const char *send_payload)
{
  size_t sent;
  FETCHcode result =
    fetch_ws_send(fetch, send_payload, strlen(send_payload), &sent, 0,
                 FETCHWS_PING);
  fprintf(stderr,
          "ws: fetch_ws_send returned %d, sent %d\n", result, (int)sent);

  return result;
}

static FETCHcode recv_pong(FETCH *fetch, const char *expected_payload)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];
  FETCHcode result = fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
  if(!result) {
    if(meta->flags & FETCHWS_PONG) {
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
      fprintf(stderr, "recv_pong: got %d bytes rflags %x\n", (int)rlen,
              meta->flags);
    }
  }
  fprintf(stderr, "ws: fetch_ws_recv returned %d, received %d\n", result,
          (int)rlen);
  return result;
}

static FETCHcode recv_any(FETCH *fetch)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];
  FETCHcode result = fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
  if(result)
    return result;

  fprintf(stderr, "recv_any: got %u bytes rflags %x\n", (int)rlen,
          meta->flags);
  return FETCHE_OK;
}

/* just close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  FETCHcode result =
    fetch_ws_send(fetch, "", 0, &sent, 0, FETCHWS_CLOSE);
  fprintf(stderr,
          "ws: fetch_ws_send returned %d, sent %u\n", result, (int)sent);
}

static void websocket(FETCH *fetch)
{
  int i = 0;
  fprintf(stderr, "ws: websocket() starts\n");
  do {
    recv_any(fetch);
    fprintf(stderr, "Send ping\n");
    if(send_ping(fetch, "foobar"))
      return;
    fprintf(stderr, "Receive pong\n");
    if(recv_pong(fetch, "foobar")) {
      printf("Connection closed\n");
      return;
    }
    sleep(2);
  } while(i++ < 10);
  websocket_close(fetch);
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);

    /* use the callback style */
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "websocket/2304");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = fetch_easy_perform(fetch);
    fprintf(stderr, "fetch_easy_perform() returned %d\n", res);
    if(res == FETCHE_OK)
      websocket(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
