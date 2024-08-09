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
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define sleep(s) Sleep((DWORD)((s)*1000))
#else
#include <unistd.h>
#endif

#include <curl/curl.h>

/* Auxiliary function that waits on the socket.
   If 'for_recv' is true it waits until data is received, if false it waits
   until data can be sent on the socket.
   If 'timeout_ms' is negative then it waits indefinitely.
   */
static int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;

  if(timeout_ms >= 0) {
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;
  }

  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);

/* Avoid this warning with pre-2020 Cygwin/MSYS releases:
 * warning: conversion to 'long unsigned int' from 'curl_socket_t' {aka 'int'}
 * may change the sign of the result [-Wsign-conversion]
 */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
  FD_SET(sockfd, &errfd); /* always check for error */

  if(for_recv) {
    FD_SET(sockfd, &infd);
  }
  else {
    FD_SET(sockfd, &outfd);
  }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd,
               ((timeout_ms >= 0) ? &tv : NULL));
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

/* close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  (void)curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
}

/* recv_any waits indefinitely for a complete websocket message of any
   known type CURLWS_TEXT, CURLWS_BINARY, CURLWS_PING, CURLWS_PONG or
   CURLWS_CLOSE.

   if a control message (PING/PONG/CLOSE) interrupts receipt of a non-control
   message (TEXT/BINARY) then the control message is either handled by libcurl
   or this function. the control message is not returned to the caller in that
   case. if possible this function will continue to wait for the complete
   non-control message to return to the caller.

   wstype receives the type. */
static CURLcode recv_any(CURL *curl, char *buffer, size_t bufsize,
  size_t *written, int *wstype)
{
  size_t rlen;
  const struct curl_ws_frame *meta;
  CURLcode result;
  int rtype = 0;
  curl_socket_t sockfd = CURL_SOCKET_BAD;

  *written = 0;
  *wstype = 0;

  if(!bufsize)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd) ||
     sockfd == CURL_SOCKET_BAD) {
    fprintf(stderr, "ws: unexpected dead connection\n");
    return CURLE_RECV_ERROR;
  }

  for(;;) {
    result = curl_ws_recv(curl, &buffer[*written], bufsize - *written,
                          &rlen, &meta);
    if(!result) {
      if((meta->flags & CURLWS_TEXT))
        rtype = CURLWS_TEXT;
      else if((meta->flags & CURLWS_BINARY))
        rtype = CURLWS_BINARY;
      else if((meta->flags & CURLWS_PING))
        rtype = CURLWS_PING;
      else if((meta->flags & CURLWS_PONG))
        rtype = CURLWS_PONG;
      else if((meta->flags & CURLWS_CLOSE))
        rtype = CURLWS_CLOSE;
      else {
        fprintf(stderr, "ws: unknown message type\n");
        return CURLE_RECV_ERROR;
      }

      /* if the received message type is different from the previous received
         type of an incomplete message then that may or may not be an error.
         websockets allows a control message (PING/PONG/CLOSE) to interrupt a
         non-control message (TEXT/BINARY). */
      if(*wstype && *wstype != rtype) {
        if((*wstype == CURLWS_TEXT || *wstype == CURLWS_BINARY) &&
           (rtype == CURLWS_PING || rtype == CURLWS_PONG ||
            rtype == CURLWS_CLOSE)) {
          /* PING and PONG can be ignored. libcurl auto-replies to PINGs unless
             raw mode is used. CLOSE should not be ignored. */
          if(rtype == CURLWS_CLOSE) {
            websocket_close(curl);
            fprintf(stderr, "ws: incomplete message interrupted by close\n");
            return CURLE_RECV_ERROR;
          }
          continue;
        }
        fprintf(stderr, "ws: incomplete message interrupted by bad type\n");
        return CURLE_RECV_ERROR;
      }

      *written += rlen;
      *wstype = rtype;

      /* the message is incomplete if the current fragment is incomplete
         (meta->bytesleft) or there are more fragments to come (CURLWS_CONT) */
      if(meta->bytesleft || (meta->flags & CURLWS_CONT)) {
        if(*written == bufsize) {
          fprintf(stderr, "ws: buffer size exceeded\n");
          /* a more robust way to handle this would be use a dynamic buffer
             that you can expand here and then continue to append to the
             incomplete message */
          return CURLE_OUT_OF_MEMORY;
        }
        continue;
      }

      /* done */
      break;
    }
    else if(result == CURLE_AGAIN) {
      /* wait indefinitely for the socket to be readable */
      int sockres = wait_on_socket(sockfd, 1, -1);
      if(sockres == 1)
        continue;
      else {
        fprintf(stderr, "ws: socket error\n");
        return CURLE_RECV_ERROR;
      }
    }
    else {
      fprintf(stderr, "ws: curl_ws_recv failed: (%d) %s\n",
              result, curl_easy_strerror(result));
      return CURLE_RECV_ERROR;
    }
  }

  fprintf(stderr, "ws: recv_any received a complete message of type %d\n",
          rtype);
  return CURLE_OK;
}

static int recv_header(CURL *curl)
{
  CURLcode result;
  char buffer[256];
  size_t written;
  int wstype;

  /* note libcurl auto responds to PINGs unless websocket raw mode is used */
  do {
    result = recv_any(curl, buffer, sizeof(buffer), &written, &wstype);
  } while(!result && (wstype == CURLWS_PING));

  if(!result) {
    /* echo.websocket.org first non-control message is a TEXT header like:
       "Request served by xyz123" */
    if(wstype == CURLWS_TEXT) {
      fprintf(stderr, "ws: received server header: %.*s\n",
              (int)written, buffer);
    }
    else if(wstype == CURLWS_CLOSE) {
      websocket_close(curl);
      fprintf(stderr, "ws: didn't receive server header, "
              "server sent CLOSE message instead.\n");
      result = CURLE_RECV_ERROR;
    }
    else {
      fprintf(stderr, "ws: didn't receive server header, "
              "server sent unexpected message type %d instead.\n",
              wstype);
    }
  }
  else {
    fprintf(stderr, "ws: recv_any() failed: (%d) %s\n",
            result, curl_easy_strerror(result));
  }

  return (int)result;
}

static int recv_pong(CURL *curl, const char *expected_payload)
{
  CURLcode result;
  char buffer[256];
  size_t written;
  int wstype;

  /* note libcurl auto responds to PINGs unless websocket raw mode is used */
  do {
    result = recv_any(curl, buffer, sizeof(buffer), &written, &wstype);
  } while(!result && (wstype == CURLWS_PING));

  if(!result) {
    if(wstype == CURLWS_PONG) {
      fprintf(stderr, "ws: received server PONG: %.*s\n",
              (int)written, buffer);
      if(written == strlen(expected_payload) &&
         !memcmp(expected_payload, buffer, written))
        fprintf(stderr, "ws: OK: server PONG same as PING payload\n");
      else
        fprintf(stderr, "ws: BAD: server PONG is NOT same as PING payload\n");
    }
    else if(wstype == CURLWS_CLOSE) {
      websocket_close(curl);
      fprintf(stderr, "ws: didn't receive server PONG, "
              "server sent CLOSE message instead.\n");
      result = CURLE_RECV_ERROR;
    }
    else {
      fprintf(stderr, "ws: didn't receive server PONG, "
              "server sent unexpected message type %d instead.\n",
              wstype);
    }
  }
  else {
    fprintf(stderr, "ws: recv_any() failed: (%d) %s\n",
            result, curl_easy_strerror(result));
  }

  return (int)result;
}

static void websocket(CURL *curl)
{
  int i = 0;

  recv_header(curl);

  do {
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
    curl_easy_setopt(curl, CURLOPT_URL, "wss://echo.websocket.org");

    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */

    /* Perform the request, res gets the return code */
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
