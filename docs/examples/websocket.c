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

#include <curl/curl.h>

static CURLcode ping(CURL *curl, const char *send_payload)
{
  CURLcode res = CURLE_OK;
  const char *buf = send_payload;
  size_t sent, blen = strlen(send_payload);

  while(blen) {
    res = curl_ws_send(curl, buf, blen, &sent, 0, CURLWS_PING);
    if(!res) {
      buf += sent; /* deduct what was sent */
      blen -= sent;
    }
    else if(res == CURLE_AGAIN) {  /* blocked on sending */
      fprintf(stderr, "ws: sent PING blocked, waiting a second\n");
      sleep(1);  /* either select() on socket or max timeout would
                    be good here. */
    }
    else /* real error sending */
      break;
  }
  if(!res)
    fprintf(stderr, "ws: sent PING with payload\n");
  return res;
}

static CURLcode recv_pong(CURL *curl, const char *expected_payload)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  char buffer[256];
  CURLcode res;

retry:
  res = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
  if(!res) {
    /* on small PING content, this example assumes the complete
     * PONG content arrives in one go. Larger frames will arrive
     * in chunks, however. */
    if(meta->flags & CURLWS_PONG) {
      int same = 0;
      if(rlen == strlen(expected_payload)) {
        if(!memcmp(expected_payload, buffer, rlen))
          same = 1;
      }
      fprintf(stderr, "ws: received PONG with %s payload back\n",
              same ? "same" : "different");
    }
    else if(meta->flags & CURLWS_TEXT) {
      fprintf(stderr, "ws: received TEXT frame '%.*s'\n", (int)rlen,
              buffer);
    }
    else if(meta->flags & CURLWS_BINARY) {
      fprintf(stderr, "ws: received BINARY frame of %u bytes\n",
              (unsigned int)rlen);
    }
    else {
      /* some other frame arrived. */
      fprintf(stderr, "ws: received frame of %u bytes rflags %x\n",
              (unsigned int)rlen, meta->flags);
      goto retry;
    }
  }
  else if(res == CURLE_AGAIN) {  /* blocked on receiving */
    fprintf(stderr, "ws: PONG not there yet, waiting a second\n");
    sleep(1);  /* either select() on socket or max timeout would
                  be good here. */
    goto retry;
  }
  if(res)
    fprintf(stderr, "ws: curl_ws_recv returned %u, received %u\n",
            (unsigned int)res, (unsigned int)rlen);
  return res;
}

/* close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  (void)curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
}

static CURLcode websocket(CURL *curl)
{
  CURLcode res;
  int i = 0;
  do {
    res = ping(curl, "foobar");
    if(res)
      break;
    res = recv_pong(curl, "foobar");
    if(res)
      break;
    sleep(1);
  } while(i++ < 10);
  websocket_close(curl);
  return res;
}

int main(int argc, const char *argv[])
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(!curl) {
    return 1; /* memory failure */
  }
  if(argc == 2)
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
  else
    curl_easy_setopt(curl, CURLOPT_URL, "wss://example.com");

  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */

  /* Perform the request, res gets the return code */
  res = curl_easy_perform(curl);
  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  else {
    /* connected and ready */
    res = websocket(curl);
  }

  /* always cleanup */
  curl_easy_cleanup(curl);
  return (int)res;
}
