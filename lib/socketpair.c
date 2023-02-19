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

#include "curl_setup.h"
#include "socketpair.h"

#if !defined(HAVE_SOCKETPAIR) && !defined(CURL_DISABLE_SOCKETPAIR)
#ifdef WIN32
/*
 * This is a socketpair() implementation for Windows.
 */
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#else
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* IPPROTO_TCP */
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif /* !INADDR_LOOPBACK */
#endif /* !WIN32 */

#include "nonblock.h" /* for curlx_nonblock */
#include "timeval.h"  /* needed before select.h */
#include "select.h"   /* for Curl_poll */

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

int Curl_socketpair(int domain, int type, int protocol,
                    curl_socket_t socks[2])
{
  union {
    struct sockaddr_in inaddr;
    struct sockaddr addr;
  } a;
  curl_socket_t listener;
  curl_socklen_t addrlen = sizeof(a.inaddr);
  int reuse = 1;
  struct pollfd pfd[1];
  (void)domain;
  (void)type;
  (void)protocol;

  listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == CURL_SOCKET_BAD)
    return -1;

  memset(&a, 0, sizeof(a));
  a.inaddr.sin_family = AF_INET;
  a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.inaddr.sin_port = 0;

  socks[0] = socks[1] = CURL_SOCKET_BAD;

#if defined(WIN32) || defined(__CYGWIN__)
  /* don't set SO_REUSEADDR on Windows */
  (void)reuse;
#ifdef SO_EXCLUSIVEADDRUSE
  {
    int exclusive = 1;
    if(setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                  (char *)&exclusive, (curl_socklen_t)sizeof(exclusive)) == -1)
      goto error;
  }
#endif
#else
  if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                (char *)&reuse, (curl_socklen_t)sizeof(reuse)) == -1)
    goto error;
#endif
  if(bind(listener, &a.addr, sizeof(a.inaddr)) == -1)
    goto error;
  if(getsockname(listener, &a.addr, &addrlen) == -1 ||
     addrlen < (int)sizeof(a.inaddr))
    goto error;
  if(listen(listener, 1) == -1)
    goto error;
  socks[0] = socket(AF_INET, SOCK_STREAM, 0);
  if(socks[0] == CURL_SOCKET_BAD)
    goto error;
  if(connect(socks[0], &a.addr, sizeof(a.inaddr)) == -1)
    goto error;

  /* use non-blocking accept to make sure we don't block forever */
  if(curlx_nonblock(listener, TRUE) < 0)
    goto error;
  pfd[0].fd = listener;
  pfd[0].events = POLLIN;
  pfd[0].revents = 0;
  (void)Curl_poll(pfd, 1, 1000); /* one second */
  socks[1] = accept(listener, NULL, NULL);
  if(socks[1] == CURL_SOCKET_BAD)
    goto error;
  else {
    struct curltime check;
    struct curltime start = Curl_now();
    char *p = (char *)&check;
    size_t s = sizeof(check);

    /* write data to the socket */
    swrite(socks[0], &start, sizeof(start));
    /* verify that we read the correct data */
    do {
      ssize_t nread;

      pfd[0].fd = socks[1];
      pfd[0].events = POLLIN;
      pfd[0].revents = 0;
      (void)Curl_poll(pfd, 1, 1000); /* one second */

      nread = sread(socks[1], p, s);
      if(nread == -1) {
        int sockerr = SOCKERRNO;
        /* Don't block forever */
        if(Curl_timediff(Curl_now(), start) > (60 * 1000))
          goto error;
        if(
#ifdef WSAEWOULDBLOCK
          /* This is how Windows does it */
          (WSAEWOULDBLOCK == sockerr)
#else
          /* errno may be EWOULDBLOCK or on some systems EAGAIN when it
             returned due to its inability to send off data without
             blocking. We therefore treat both error codes the same here */
          (EWOULDBLOCK == sockerr) || (EAGAIN == sockerr) ||
          (EINTR == sockerr) || (EINPROGRESS == sockerr)
#endif
          ) {
          continue;
        }
        goto error;
      }
      s -= nread;
      if(s) {
        p += nread;
        continue;
      }
      if(memcmp(&start, &check, sizeof(check)))
        goto error;
      break;
    } while(1);
  }

  sclose(listener);
  return 0;

  error:
  sclose(listener);
  sclose(socks[0]);
  sclose(socks[1]);
  return -1;
}

#endif /* ! HAVE_SOCKETPAIR */
