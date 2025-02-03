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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * Demonstrate fetch_easy_send() and fetch_easy_recv() usage.
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/* Avoid warning in FD_SET() with pre-2020 Cygwin/MSYS releases:
 * warning: conversion to 'long unsigned int' from 'fetch_socket_t' {aka 'int'}
 * may change the sign of the result [-Wsign-conversion]
 */
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wsign-conversion"
#ifdef __DJGPP__
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
#elif defined(_MSC_VER)
#pragma warning(disable : 4127) /* conditional expression is constant */
#endif

/* Auxiliary function that waits on the socket. */
static int wait_on_socket(fetch_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;

#if defined(MSDOS) || defined(__AMIGA__)
  tv.tv_sec = (time_t)(timeout_ms / 1000);
  tv.tv_usec = (time_t)(timeout_ms % 1000) * 1000;
#else
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;
#endif

  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);

  FD_SET(sockfd, &errfd); /* always check for error */

  if (for_recv)
  {
    FD_SET(sockfd, &infd);
  }
  else
  {
    FD_SET(sockfd, &outfd);
  }

  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}

int main(void)
{
  FETCH *fetch;
  /* Minimalistic http request */
  const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
  size_t request_len = strlen(request);

  /* A general note of caution here: if you are using fetch_easy_recv() or
     fetch_easy_send() to implement HTTP or _any_ other protocol libfetch
     supports "natively", you are doing it wrong and you should stop.

     This example uses HTTP only to show how to use this API, it does not
     suggest that writing an application doing this is sensible.
  */

  fetch = fetch_easy_init();
  if (fetch)
  {
    FETCHcode res;
    fetch_socket_t sockfd;
    size_t nsent_total = 0;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    /* Do not do the transfer - only connect to host */
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
    res = fetch_easy_perform(fetch);

    if (res != FETCHE_OK)
    {
      printf("Error: %s\n", fetch_easy_strerror(res));
      return 1;
    }

    /* Extract the socket from the fetch handle - we need it for waiting. */
    res = fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sockfd);

    if (res != FETCHE_OK)
    {
      printf("Error: %s\n", fetch_easy_strerror(res));
      return 1;
    }

    printf("Sending request.\n");

    do
    {
      /* Warning: This example program may loop indefinitely.
       * A production-quality program must define a timeout and exit this loop
       * as soon as the timeout has expired. */
      size_t nsent;
      do
      {
        nsent = 0;
        res = fetch_easy_send(fetch, request + nsent_total,
                              request_len - nsent_total, &nsent);
        nsent_total += nsent;

        if (res == FETCHE_AGAIN && !wait_on_socket(sockfd, 0, 60000L))
        {
          printf("Error: timeout.\n");
          return 1;
        }
      } while (res == FETCHE_AGAIN);

      if (res != FETCHE_OK)
      {
        printf("Error: %s\n", fetch_easy_strerror(res));
        return 1;
      }

      printf("Sent %lu bytes.\n", (unsigned long)nsent);

    } while (nsent_total < request_len);

    printf("Reading response.\n");

    for (;;)
    {
      /* Warning: This example program may loop indefinitely (see above). */
      char buf[1024];
      size_t nread;
      do
      {
        nread = 0;
        res = fetch_easy_recv(fetch, buf, sizeof(buf), &nread);

        if (res == FETCHE_AGAIN && !wait_on_socket(sockfd, 1, 60000L))
        {
          printf("Error: timeout.\n");
          return 1;
        }
      } while (res == FETCHE_AGAIN);

      if (res != FETCHE_OK)
      {
        printf("Error: %s\n", fetch_easy_strerror(res));
        break;
      }

      if (nread == 0)
      {
        /* end of the response */
        break;
      }

      printf("Received %lu bytes.\n", (unsigned long)nread);
    }

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
