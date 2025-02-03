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
 * WebSocket using CONNECT_ONLY
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#define sleep(s) Sleep((DWORD)(s))
#else
#include <unistd.h>
#endif

#include <fetch/fetch.h>

static int ping(FETCH *fetch, const char *send_payload)
{
  size_t sent;
  FETCHcode result =
      fetch_ws_send(fetch, send_payload, strlen(send_payload), &sent, 0,
                    FETCHWS_PING);
  return (int)result;
}

static int recv_pong(FETCH *fetch, const char *expected_payload)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];
  FETCHcode result = fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
  if (!result)
  {
    if (meta->flags & FETCHWS_PONG)
    {
      int same = 0;
      fprintf(stderr, "ws: got PONG back\n");
      if (rlen == strlen(expected_payload))
      {
        if (!memcmp(expected_payload, buffer, rlen))
        {
          fprintf(stderr, "ws: got the same payload back\n");
          same = 1;
        }
      }
      if (!same)
        fprintf(stderr, "ws: did NOT get the same payload back\n");
    }
    else
    {
      fprintf(stderr, "recv_pong: got %u bytes rflags %x\n", (int)rlen,
              meta->flags);
    }
  }
  fprintf(stderr, "ws: fetch_ws_recv returned %u, received %u\n",
          (unsigned int)result, (unsigned int)rlen);
  return (int)result;
}

static FETCHcode recv_any(FETCH *fetch)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];

  return fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
}

/* close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  (void)fetch_ws_send(fetch, "", 0, &sent, 0, FETCHWS_CLOSE);
}

static void websocket(FETCH *fetch)
{
  int i = 0;
  do
  {
    recv_any(fetch);
    if (ping(fetch, "foobar"))
      return;
    if (recv_pong(fetch, "foobar"))
    {
      return;
    }
    sleep(2);
  } while (i++ < 10);
  websocket_close(fetch);
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "wss://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 2L); /* websocket style */

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));
    else
    {
      /* connected and ready */
      websocket(fetch);
    }

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
