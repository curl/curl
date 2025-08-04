#ifndef HEADER_CURL_SELECT_H
#define HEADER_CURL_SELECT_H
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

#ifdef HAVE_POLL_H
#include <poll.h>
#elif defined(HAVE_SYS_POLL_H)
#include <sys/poll.h>
#endif

/*
 * Definition of pollfd struct and constants for platforms lacking them.
 */

#if !defined(HAVE_SYS_POLL_H) && \
    !defined(HAVE_POLL_H) && \
    !defined(POLLIN)

#define POLLIN      0x01
#define POLLPRI     0x02
#define POLLOUT     0x04
#define POLLERR     0x08
#define POLLHUP     0x10
#define POLLNVAL    0x20

struct pollfd
{
    curl_socket_t fd;
    short   events;
    short   revents;
};

#endif

#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLPRI
#endif

/* there are three CSELECT defines that are defined in the public header that
   are exposed to users, but this *IN2 bit is only ever used internally and
   therefore defined here */
#define CURL_CSELECT_IN2 (CURL_CSELECT_ERR << 1)

int Curl_socket_check(curl_socket_t readfd, curl_socket_t readfd2,
                      curl_socket_t writefd,
                      timediff_t timeout_ms);
#define SOCKET_READABLE(x,z) \
  Curl_socket_check(x, CURL_SOCKET_BAD, CURL_SOCKET_BAD, z)
#define SOCKET_WRITABLE(x,z) \
  Curl_socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, x, z)

int Curl_poll(struct pollfd ufds[], unsigned int nfds, timediff_t timeout_ms);

/*
   With Winsock the valid range is [0..INVALID_SOCKET-1] according to
   https://docs.microsoft.com/en-us/windows/win32/winsock/socket-data-type-2
*/
#ifdef USE_WINSOCK
#define VALID_SOCK(s) ((s) < INVALID_SOCKET)
#define FDSET_SOCK(x) 1
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(SOCKEINVAL); \
    return -1; \
  } \
} while(0)
#else
#define VALID_SOCK(s) ((s) >= 0)

/* If the socket is small enough to get set or read from an fdset */
#define FDSET_SOCK(s) ((s) < FD_SETSIZE)

#define VERIFY_SOCK(x) do {                     \
    if(!VALID_SOCK(x) || !FDSET_SOCK(x)) {      \
      SET_SOCKERRNO(SOCKEINVAL);                \
      return -1;                                \
    }                                           \
  } while(0)
#endif


/* we support N sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 16

/* the write bits start at bit 16 for the *getsock() bitmap */
#define GETSOCK_WRITEBITSTART 16

#define GETSOCK_BLANK 0U /* no bits set */

/* set the bit for the given sock number to make the bitmap for writable */
#define GETSOCK_WRITESOCK(x) (1U << (GETSOCK_WRITEBITSTART + (x)))

/* set the bit for the given sock number to make the bitmap for readable */
#define GETSOCK_READSOCK(x) (1U << (x))

/* mask for checking if read and/or write is set for index x */
#define GETSOCK_MASK_RW(x) (GETSOCK_READSOCK(x)|GETSOCK_WRITESOCK(x))


/* Polling requested by an easy handle.
 * `action` is CURL_POLL_IN, CURL_POLL_OUT or CURL_POLL_INOUT.
 */
struct easy_pollset {
  curl_socket_t sockets[MAX_SOCKSPEREASYHANDLE];
  unsigned int num;
  unsigned char actions[MAX_SOCKSPEREASYHANDLE];
};

void Curl_pollset_reset(struct Curl_easy *data,
                        struct easy_pollset *ps);

/* Change the poll flags (CURL_POLL_IN/CURL_POLL_OUT) to the poll set for
 * socket `sock`. If the socket is not already part of the poll set, it
 * will be added.
 * If the socket is present and all poll flags are cleared, it will be removed.
 */
void Curl_pollset_change(struct Curl_easy *data,
                         struct easy_pollset *ps, curl_socket_t sock,
                         int add_flags, int remove_flags);

void Curl_pollset_set(struct Curl_easy *data,
                      struct easy_pollset *ps, curl_socket_t sock,
                      bool do_in, bool do_out);

#define Curl_pollset_add_in(data, ps, sock) \
          Curl_pollset_change((data), (ps), (sock), CURL_POLL_IN, 0)
#define Curl_pollset_add_out(data, ps, sock) \
          Curl_pollset_change((data), (ps), (sock), CURL_POLL_OUT, 0)
#define Curl_pollset_add_inout(data, ps, sock) \
          Curl_pollset_change((data), (ps), (sock), \
                               CURL_POLL_IN|CURL_POLL_OUT, 0)
#define Curl_pollset_set_in_only(data, ps, sock) \
          Curl_pollset_change((data), (ps), (sock), \
                               CURL_POLL_IN, CURL_POLL_OUT)
#define Curl_pollset_set_out_only(data, ps, sock) \
          Curl_pollset_change((data), (ps), (sock), \
                               CURL_POLL_OUT, CURL_POLL_IN)

void Curl_pollset_add_socks(struct Curl_easy *data,
                            struct easy_pollset *ps,
                            unsigned int (*socks_cb)(struct Curl_easy *data,
                                                     curl_socket_t *socks));

/**
 * Check if the pollset, as is, wants to read and/or write regarding
 * the given socket.
 */
void Curl_pollset_check(struct Curl_easy *data,
                        struct easy_pollset *ps, curl_socket_t sock,
                        bool *pwant_read, bool *pwant_write);

/**
 * Return TRUE if the pollset contains socket with CURL_POLL_IN.
 */
bool Curl_pollset_want_read(struct Curl_easy *data,
                            struct easy_pollset *ps,
                            curl_socket_t sock);

struct curl_pollfds {
  struct pollfd *pfds;
  unsigned int n;
  unsigned int count;
  BIT(allocated_pfds);
};

void Curl_pollfds_init(struct curl_pollfds *cpfds,
                       struct pollfd *static_pfds,
                       unsigned int static_count);

void Curl_pollfds_reset(struct curl_pollfds *cpfds);

void Curl_pollfds_cleanup(struct curl_pollfds *cpfds);

CURLcode Curl_pollfds_add_ps(struct curl_pollfds *cpfds,
                             struct easy_pollset *ps);

CURLcode Curl_pollfds_add_sock(struct curl_pollfds *cpfds,
                               curl_socket_t sock, short events);

struct Curl_waitfds {
  struct curl_waitfd *wfds;
  unsigned int n;
  unsigned int count;
};

void Curl_waitfds_init(struct Curl_waitfds *cwfds,
                       struct curl_waitfd *static_wfds,
                       unsigned int static_count);

unsigned int Curl_waitfds_add_ps(struct Curl_waitfds *cwfds,
                                 struct easy_pollset *ps);

#endif /* HEADER_CURL_SELECT_H */
