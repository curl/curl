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
 * Demonstrate curl_easy_send() and curl_easy_recv() usage.
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

/* Auxiliary function that waits on the socket. */
static int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;

  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;

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
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4127)  /* conditional expression is constant */
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
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}

int main(void)
{
  CURL *curl;
  /* Minimalistic http request */
  const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
  size_t request_len = strlen(request);

  /* A general note of caution here: if you are using curl_easy_recv() or
     curl_easy_send() to implement HTTP or _any_ other protocol libcurl
     supports "natively", you are doing it wrong and you should stop.

     This example uses HTTP only to show how to use this API, it does not
     suggest that writing an application doing this is sensible.
  */

  curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_socket_t sockfd;
    size_t nsent_total = 0;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    /* Do not do the transfer - only connect to host */
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
      printf("Error: %s\n", curl_easy_strerror(res));
      return 1;
    }

    /* Extract the socket from the curl handle - we need it for waiting. */
    res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);

    if(res != CURLE_OK) {
      printf("Error: %s\n", curl_easy_strerror(res));
      return 1;
    }

    printf("Sending request.\n");

    do {
      /* Warning: This example program may loop indefinitely.
       * A production-quality program must define a timeout and exit this loop
       * as soon as the timeout has expired. */
      size_t nsent;
      do {
        nsent = 0;
        res = curl_easy_send(curl, request + nsent_total,
            request_len - nsent_total, &nsent);
        nsent_total += nsent;

        if(res == CURLE_AGAIN && !wait_on_socket(sockfd, 0, 60000L)) {
          printf("Error: timeout.\n");
          return 1;
        }
      } while(res == CURLE_AGAIN);

      if(res != CURLE_OK) {
        printf("Error: %s\n", curl_easy_strerror(res));
        return 1;
      }

      printf("Sent %lu bytes.\n", (unsigned long)nsent);

    } while(nsent_total < request_len);

    printf("Reading response.\n");

    for(;;) {
      /* Warning: This example program may loop indefinitely (see above). */
      char buf[1024];
      size_t nread;
      do {
        nread = 0;
        res = curl_easy_recv(curl, buf, sizeof(buf), &nread);

        if(res == CURLE_AGAIN && !wait_on_socket(sockfd, 1, 60000L)) {
          printf("Error: timeout.\n");
          return 1;
        }
      } while(res == CURLE_AGAIN);

      if(res != CURLE_OK) {
        printf("Error: %s\n", curl_easy_strerror(res));
        break;
      }

      if(nread == 0) {
        /* end of the response */
        break;
      }

      printf("Received %lu bytes.\n", (unsigned long)nread);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
