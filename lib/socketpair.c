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
#include "urldata.h"
#include "rand.h"
#include "curlx/nonblock.h"

#ifndef CURL_DISABLE_SOCKETPAIR

/* choose implementation */
#ifdef USE_EVENTFD

#include <sys/eventfd.h>

static int wakeup_eventfd(curl_socket_t socks[2], bool nonblocking)
{
  int efd = eventfd(0, nonblocking ? EFD_CLOEXEC | EFD_NONBLOCK : EFD_CLOEXEC);
  if(efd == -1) {
    socks[0] = socks[1] = CURL_SOCKET_BAD;
    return -1;
  }
  socks[0] = socks[1] = efd;
  return 0;
}

#elif defined(HAVE_PIPE)

#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif

static int wakeup_pipe(curl_socket_t socks[2], bool nonblocking)
{
#ifdef HAVE_PIPE2
  int flags = nonblocking ? O_NONBLOCK | O_CLOEXEC : O_CLOEXEC;
  if(pipe2(socks, flags))
    return -1;
#else
  if(pipe(socks))
    return -1;
#ifdef HAVE_FCNTL
  if(fcntl(socks[0], F_SETFD, FD_CLOEXEC) ||
     fcntl(socks[1], F_SETFD, FD_CLOEXEC)) {
    sclose(socks[0]);
    sclose(socks[1]);
    socks[0] = socks[1] = CURL_SOCKET_BAD;
    return -1;
  }
#endif
  if(nonblocking) {
    if(curlx_nonblock(socks[0], TRUE) < 0 ||
       curlx_nonblock(socks[1], TRUE) < 0) {
      sclose(socks[0]);
      sclose(socks[1]);
      socks[0] = socks[1] = CURL_SOCKET_BAD;
      return -1;
    }
  }
#endif

  return 0;
}

#elif defined(HAVE_SOCKETPAIR)  /* !USE_EVENTFD && !HAVE_PIPE */

#ifndef USE_UNIX_SOCKETS
#error "unsupported Unix domain and socketpair build combo"
#endif

static int wakeup_socketpair(curl_socket_t socks[2], bool nonblocking)
{
  int type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
  type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
  if(nonblocking)
    type |= SOCK_NONBLOCK;
#endif

  if(CURL_SOCKETPAIR(AF_UNIX, type, 0, socks))
    return -1;
#ifndef SOCK_NONBLOCK
  if(nonblocking) {
    if(curlx_nonblock(socks[0], TRUE) < 0 ||
       curlx_nonblock(socks[1], TRUE) < 0) {
      sclose(socks[0]);
      sclose(socks[1]);
      return -1;
    }
  }
#endif
  return 0;
}

#else /* !USE_EVENTFD && !HAVE_PIPE && !HAVE_SOCKETPAIR */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* for IPPROTO_TCP */
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

#include "select.h"   /* for Curl_poll */

static int wakeup_inet(curl_socket_t socks[2], bool nonblocking)
{
  union {
    struct sockaddr_in inaddr;
    struct sockaddr addr;
  } a;
  curl_socket_t listener;
  curl_socklen_t addrlen = sizeof(a.inaddr);
  int reuse = 1;
  struct pollfd pfd[1];

  listener = CURL_SOCKET(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listener == CURL_SOCKET_BAD)
    return -1;

  memset(&a, 0, sizeof(a));
  a.inaddr.sin_family = AF_INET;
  a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.inaddr.sin_port = 0;

  socks[0] = socks[1] = CURL_SOCKET_BAD;

#if defined(_WIN32) || defined(__CYGWIN__)
  /* do not set SO_REUSEADDR on Windows */
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
  socks[0] = CURL_SOCKET(AF_INET, SOCK_STREAM, 0);
  if(socks[0] == CURL_SOCKET_BAD)
    goto error;
  if(connect(socks[0], &a.addr, sizeof(a.inaddr)) == -1)
    goto error;

  /* use non-blocking accept to make sure we do not block forever */
  if(curlx_nonblock(listener, TRUE) < 0)
    goto error;
  pfd[0].fd = listener;
  pfd[0].events = POLLIN;
  pfd[0].revents = 0;
  (void)Curl_poll(pfd, 1, 1000); /* one second */
  socks[1] = CURL_ACCEPT(listener, NULL, NULL);
  if(socks[1] == CURL_SOCKET_BAD)
    goto error;
  else {
    struct curltime start = curlx_now();
    char rnd[9];
    char check[sizeof(rnd)];
    char *p = &check[0];
    size_t s = sizeof(check);

    if(Curl_rand(NULL, (unsigned char *)rnd, sizeof(rnd)))
      goto error;

    /* write data to the socket */
    swrite(socks[0], rnd, sizeof(rnd));
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
        /* Do not block forever */
        if(curlx_timediff_ms(curlx_now(), start) > (60 * 1000))
          goto error;
        if(
#ifdef USE_WINSOCK
           /* This is how Windows does it */
           (SOCKEWOULDBLOCK == sockerr)
#else
           /* errno may be EWOULDBLOCK or on some systems EAGAIN when it
              returned due to its inability to send off data without
              blocking. We therefore treat both error codes the same here */
           (SOCKEWOULDBLOCK == sockerr) || (EAGAIN == sockerr) ||
           (SOCKEINTR == sockerr) || (SOCKEINPROGRESS == sockerr)
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
      if(memcmp(rnd, check, sizeof(check)))
        goto error;
      break;
    } while(1);
  }

  if(nonblocking)
    if(curlx_nonblock(socks[0], TRUE) < 0 ||
       curlx_nonblock(socks[1], TRUE) < 0)
      goto error;
  sclose(listener);
  return 0;

error:
  sclose(listener);
  sclose(socks[0]);
  sclose(socks[1]);
  return -1;
}

#endif /* choose implementation */

int Curl_wakeup_init(curl_socket_t socks[2], bool nonblocking)
{
#ifdef USE_EVENTFD
  return wakeup_eventfd(socks, nonblocking);
#elif defined(HAVE_PIPE)
  return wakeup_pipe(socks, nonblocking);
#elif defined(HAVE_SOCKETPAIR)
  return wakeup_socketpair(socks, nonblocking);
#else
  return wakeup_inet(socks, nonblocking);
#endif
}

#if defined(USE_EVENTFD) || defined(HAVE_PIPE)

#define wakeup_write        write
#define wakeup_read         read
#define wakeup_close        close

#else /* !USE_EVENTFD && !HAVE_PIPE */

#define wakeup_write        swrite
#define wakeup_read         sread
#define wakeup_close        sclose

#endif

int Curl_wakeup_signal(curl_socket_t socks[2])
{
  int err = 0;
#ifdef USE_EVENTFD
  const uint64_t buf[1] = { 1 };
#else
  const char buf[1] = { 1 };
#endif

  while(1) {
    if(wakeup_write(socks[1], buf, sizeof(buf)) < 0) {
      err = SOCKERRNO;
#ifdef USE_WINSOCK
      if(err == SOCKEWOULDBLOCK)
        err = 0; /* wakeup is already ongoing */
#else
      if(SOCKEINTR == err)
        continue;
      if((err == SOCKEWOULDBLOCK) || (err == EAGAIN))
        err = 0; /* wakeup is already ongoing */
#endif
    }
    break;
  }
  return err;
}

CURLcode Curl_wakeup_consume(curl_socket_t socks[2], bool all)
{
  char buf[64];
  ssize_t rc;
  CURLcode result = CURLE_OK;

  do {
    rc = wakeup_read(socks[0], buf, sizeof(buf));
    if(!rc)
      break;
    else if(rc < 0) {
#ifdef USE_WINSOCK
      if(SOCKERRNO == SOCKEWOULDBLOCK)
        break;
#else
      if(SOCKEINTR == SOCKERRNO)
        continue;
      if((SOCKERRNO == SOCKEWOULDBLOCK) || (SOCKERRNO == EAGAIN))
        break;
#endif
      result = CURLE_READ_ERROR;
      break;
    }
  } while(all);
  return result;
}

void Curl_wakeup_destroy(curl_socket_t socks[2])
{
#ifndef USE_EVENTFD
  if(socks[1] != CURL_SOCKET_BAD)
    wakeup_close(socks[1]);
#endif
  if(socks[0] != CURL_SOCKET_BAD)
    wakeup_close(socks[0]);
  socks[0] = socks[1] = CURL_SOCKET_BAD;
}

#endif /* !CURL_DISABLE_SOCKETPAIR */
