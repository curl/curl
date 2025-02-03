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
 * Pass in a custom socket for libfetch to use.
 * </DESC>
 */
#ifdef _WIN32
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS /* for inet_addr() */
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fetch/fetch.h>

#ifdef _WIN32
#define close closesocket
#else
#include <sys/types.h>  /*  socket types              */
#include <sys/socket.h> /*  socket definitions        */
#include <netinet/in.h>
#include <arpa/inet.h> /*  inet (3) functions        */
#include <unistd.h>    /*  misc. Unix functions      */
#endif

#include <errno.h>

/* The IP address and port number to connect to */
#define IPADDR "127.0.0.1"
#define PORTNUM 80

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

static int closecb(void *clientp, fetch_socket_t item)
{
  (void)clientp;
  printf("libfetch wants to close %d now\n", (int)item);
  return 0;
}

static fetch_socket_t opensocket(void *clientp,
                                 fetchsocktype purpose,
                                 struct fetch_sockaddr *address)
{
  fetch_socket_t sockfd;
  (void)purpose;
  (void)address;
  sockfd = *(fetch_socket_t *)clientp;
  /* the actual externally set socket is passed in via the OPENSOCKETDATA
     option */
  return sockfd;
}

static int sockopt_callback(void *clientp, fetch_socket_t fetchfd,
                            fetchsocktype purpose)
{
  (void)clientp;
  (void)fetchfd;
  (void)purpose;
  /* This return code was added in libfetch 7.21.5 */
  return FETCH_SOCKOPT_ALREADY_CONNECTED;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  struct sockaddr_in servaddr; /*  socket address structure  */
  fetch_socket_t sockfd;

#ifdef _WIN32
  WSADATA wsaData;
  int initwsa = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (initwsa)
  {
    printf("WSAStartup failed: %d\n", initwsa);
    return 1;
  }
#endif

  fetch = fetch_easy_init();
  if (fetch)
  {
    /*
     * Note that libfetch internally thinks that you connect to the host and
     * port that you specify in the URL option.
     */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://99.99.99.99:9999");

    /* Create the socket "manually" */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == FETCH_SOCKET_BAD)
    {
      printf("Error creating listening socket.\n");
      return 3;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORTNUM);

    servaddr.sin_addr.s_addr = inet_addr(IPADDR);
    if (INADDR_NONE == servaddr.sin_addr.s_addr)
    {
      close(sockfd);
      return 2;
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) ==
        -1)
    {
      close(sockfd);
      printf("client error: connect: %s\n", strerror(errno));
      return 1;
    }

    /* no progress meter please */
    fetch_easy_setopt(fetch, FETCHOPT_NOPROGRESS, 1L);

    /* send all data to this function  */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_data);

    /* call this function to get a socket */
    fetch_easy_setopt(fetch, FETCHOPT_OPENSOCKETFUNCTION, opensocket);
    fetch_easy_setopt(fetch, FETCHOPT_OPENSOCKETDATA, &sockfd);

    /* call this function to close sockets */
    fetch_easy_setopt(fetch, FETCHOPT_CLOSESOCKETFUNCTION, closecb);
    fetch_easy_setopt(fetch, FETCHOPT_CLOSESOCKETDATA, &sockfd);

    /* call this function to set options for the socket */
    fetch_easy_setopt(fetch, FETCHOPT_SOCKOPTFUNCTION, sockopt_callback);

    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);

    close(sockfd);

    if (res)
    {
      printf("libfetch error: %d\n", res);
      return 4;
    }
  }

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
