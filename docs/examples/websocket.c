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
#include <unistd.h>
#include <curl/curl.h>

/* Avoid warning in FD_SET() with pre-2020 Cygwin/MSYS releases:
 * warning: conversion to 'long unsigned int' from 'curl_socket_t' {aka 'int'}
 * may change the sign of the result [-Wsign-conversion]
 */
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

/* Auxiliary function that waits on the socket. */
static int wait_on_socket(curl_socket_t sockfd, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;

  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;

  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);

  FD_SET(sockfd, &errfd); /* always check for error */
  FD_SET(sockfd, &infd);

  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}

static int ping(CURL *curl, const char *send_payload)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, send_payload, strlen(send_payload), &sent, 0,
                 CURLWS_PING);
  return (int)result;
}

static int recv_pong(CURL *curl, const char *expected_payload)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  char buffer[256];
  CURLcode result;
  curl_socket_t sockfd;

  result = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);

  if(result != CURLE_OK) {
    printf("Error: %s\n", curl_easy_strerror(result));
    return 1;
  }

  do {
    result = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
    if(result == CURLE_AGAIN && !wait_on_socket(sockfd, 1000)) {
      printf("Error: timeout.\n");
      break;
    }
  } while(result == CURLE_AGAIN);

  if(result != CURLE_OK) {
    fprintf(stderr, "ws: curl_ws_recv returned %u, received %u\n",
            (unsigned int)result, (unsigned int)rlen);
    return (int)result;
  }

  if(meta->flags & CURLWS_PONG) {
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
    fprintf(stderr, "recv_pong: got %u bytes rflags %x\n", (int)rlen,
            meta->flags);
  }

  return (int)result;
}

static int recv_any(CURL *curl)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  char buffer[256];
  CURLcode result = curl_ws_recv(curl, buffer, sizeof(buffer), &rlen, &meta);
  if(result)
    return result;

  return 0;
}

/* close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  (void)curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
}

static void websocket(CURL *curl)
{
  int i = 0;
  do {
    recv_any(curl);
    if(ping(curl, "foobar"))
      return;
    if(recv_pong(curl, "foobar")) {
      return;
    }
    sleep(2);
  } while(i++ < 10);
  websocket_close(curl);
}

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "wss://example.com");

    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    else {
      /* connected and ready */
      websocket(curl);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
