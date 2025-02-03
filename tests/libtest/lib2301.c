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
#if 0

static FETCHcode send_ping(FETCH *fetch, const char *send_payload)
{
  size_t sent;
  FETCHcode result =
    fetch_ws_send(fetch, send_payload, strlen(send_payload), &sent, FETCHWS_PING);
  fprintf(stderr,
          "ws: fetch_ws_send returned %d, sent %d\n", result, (int)sent);

  return result;
}

static FETCHcode recv_pong(FETCH *fetch, const char *expected_payload)
{
  size_t rlen;
  unsigned int rflags;
  char buffer[256];
  FETCHcode result =
    fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &rflags);
  if(rflags & FETCHWS_PONG) {
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
  fprintf(stderr, "ws: fetch_ws_recv returned %d, received %d\n", result,
          (int)rlen);
  return result;
}

/* just close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  FETCHcode result =
    fetch_ws_send(fetch, "", 0, &sent, FETCHWS_CLOSE);
  fprintf(stderr,
          "ws: fetch_ws_send returned %d, sent %d\n", result, (int)sent);
}

static void websocket(FETCH *fetch)
{
  int i = 0;
  fprintf(stderr, "ws: websocket() starts\n");
  do {
    if(send_ping(fetch, "foobar"))
      return;
    if(recv_pong(fetch, "foobar"))
      return;
    sleep(2);
  } while(i++ < 10);
  websocket_close(fetch);
}

#endif

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  FETCH *easy = p;
  unsigned char *buffer = (unsigned char *)b;
  size_t i;
  size_t sent;
  unsigned char pong[] = {
    0x8a, 0x0
  };
  size_t incoming = nitems;
  fprintf(stderr, "Called FETCHOPT_WRITEFUNCTION with %d bytes: ",
          (int)nitems);
  for(i = 0; i < nitems; i++)
    fprintf(stderr, "%02x ", (unsigned char)buffer[i]);
  fprintf(stderr, "\n");
  (void)size;
  if(buffer[0] == 0x89) {
    FETCHcode result;
    fprintf(stderr, "send back a simple PONG\n");
    result = fetch_ws_send(easy, pong, 2, &sent, 0, 0);
    if(result)
      nitems = 0;
  }
  if(nitems != incoming)
    fprintf(stderr, "returns error from callback\n");
  return nitems;
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
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "webbie-sox/3");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_WS_OPTIONS, FETCHWS_RAW_MODE);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, fetch);
    res = fetch_easy_perform(fetch);
    fprintf(stderr, "fetch_easy_perform() returned %d\n", res);
#if 0
    if(res == FETCHE_OK)
      websocket(fetch);
#endif
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return res;
}

#else /* no WebSockets */
NO_SUPPORT_BUILT_IN
#endif
