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


/* Keep the sockets to poll for an easy handle.
 * `actions` are bitmaps of CURL_POLL_IN and CURL_POLL_OUT.
 * Starts with small capacity, grows on demand.
 */
#define EZ_POLLSET_DEF_COUNT    2

struct easy_pollset {
  curl_socket_t *sockets;
  unsigned char *actions;
  unsigned int n;
  unsigned int count;
#ifdef DEBUGBUILD
  int init;
#endif
  curl_socket_t def_sockets[EZ_POLLSET_DEF_COUNT];
  unsigned char def_actions[EZ_POLLSET_DEF_COUNT];
};

#ifdef DEBUGBUILD
#define CURL_EASY_POLLSET_MAGIC  0x7a657370
#endif


/* allocate and initialise */
struct easy_pollset *Curl_pollset_create(void);

/* Initialize before first use */
void Curl_pollset_init(struct easy_pollset *ps);
/* Free any allocated resources */
void Curl_pollset_cleanup(struct easy_pollset *ps);
/* Reset to an empty pollset */
void Curl_pollset_reset(struct easy_pollset *ps);
/* Move pollset from to pollset to, replacing all in to,
 * leaving from empty. */
void Curl_pollset_move(struct easy_pollset *to, struct easy_pollset *from);

/* Change the poll flags (CURL_POLL_IN/CURL_POLL_OUT) to the poll set for
 * socket `sock`. If the socket is not already part of the poll set, it
 * will be added.
 * If the socket is present and all poll flags are cleared, it will be removed.
 */
CURLcode Curl_pollset_change(struct Curl_easy *data,
                             struct easy_pollset *ps, curl_socket_t sock,
                             int add_flags, int remove_flags);

CURLcode Curl_pollset_set(struct Curl_easy *data,
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

/* return < = on error, 0 on timeout or how many sockets are ready */
int Curl_pollset_poll(struct Curl_easy *data,
                      struct easy_pollset *ps,
                      timediff_t timeout_ms);

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
