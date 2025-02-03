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
/* <DESC>
 * WebSockets pingpong
 * </DESC>
 */
/* fetch stuff */
#include "fetch_setup.h"
#include <fetch/fetch.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/time.h>
#endif

#ifndef FETCH_DISABLE_WEBSOCKETS

static FETCHcode ping(FETCH *fetch, const char *send_payload)
{
  size_t sent;
  FETCHcode result =
      fetch_ws_send(fetch, send_payload, strlen(send_payload), &sent, 0,
                    FETCHWS_PING);
  fprintf(stderr,
          "ws: fetch_ws_send returned %u, sent %u\n", (int)result, (int)sent);

  return result;
}

static FETCHcode recv_pong(FETCH *fetch, const char *expected_payload)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];
  FETCHcode result = fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
  if (result)
  {
    fprintf(stderr, "ws: fetch_ws_recv returned %u, received %ld\n",
            (int)result, (long)rlen);
    return result;
  }

  if (!(meta->flags & FETCHWS_PONG))
  {
    fprintf(stderr, "recv_pong: wrong frame, got %d bytes rflags %x\n",
            (int)rlen, meta->flags);
    return FETCHE_RECV_ERROR;
  }

  fprintf(stderr, "ws: got PONG back\n");
  if (rlen == strlen(expected_payload) &&
      !memcmp(expected_payload, buffer, rlen))
  {
    fprintf(stderr, "ws: got the same payload back\n");
    return FETCHE_OK;
  }
  fprintf(stderr, "ws: did NOT get the same payload back\n");
  return FETCHE_RECV_ERROR;
}

/* just close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  FETCHcode result =
      fetch_ws_send(fetch, "", 0, &sent, 0, FETCHWS_CLOSE);
  fprintf(stderr,
          "ws: fetch_ws_send returned %u, sent %u\n", (int)result, (int)sent);
}

#if defined(__TANDEM)
#include <cextdecs.h(PROCESS_DELAY_)>
#endif
static FETCHcode pingpong(FETCH *fetch, const char *payload)
{
  FETCHcode res;
  int i;

  res = ping(fetch, payload);
  if (res)
    return res;
  for (i = 0; i < 10; ++i)
  {
    fprintf(stderr, "Receive pong\n");
    res = recv_pong(fetch, payload);
    if (res == FETCHE_AGAIN)
    {
#ifdef _WIN32
      Sleep(100);
#elif defined(__TANDEM)
      /* NonStop only defines usleep when building for a threading model */
#if defined(_PUT_MODEL_) || defined(_KLT_MODEL_)
      usleep(100 * 1000);
#else
      PROCESS_DELAY_(100 * 1000);
#endif
#else
      usleep(100 * 1000);
#endif
      continue;
    }
    websocket_close(fetch);
    return res;
  }
  websocket_close(fetch);
  return FETCHE_RECV_ERROR;
}

#endif

int main(int argc, char *argv[])
{
#ifndef FETCH_DISABLE_WEBSOCKETS
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  const char *url, *payload;

  if (argc != 3)
  {
    fprintf(stderr, "usage: ws-pingpong url payload\n");
    return 2;
  }
  url = argv[1];
  payload = argv[2];

  fetch_global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, url);

    /* use the callback style */
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "ws-pingpong");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = fetch_easy_perform(fetch);
    fprintf(stderr, "fetch_easy_perform() returned %u\n", (int)res);
    if (res == FETCHE_OK)
      res = pingpong(fetch, payload);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return (int)res;

#else  /* !FETCH_DISABLE_WEBSOCKETS */
  (void)argc;
  (void)argv;
  fprintf(stderr, "WebSockets not enabled in libfetch\n");
  return 1;
#endif /* FETCH_DISABLE_WEBSOCKETS */
}
