#ifndef __SELECT_H
#define __SELECT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif defined(HAVE_POLL_H)
#include <poll.h>
#endif

/*
 * poll() function on Windows Vista and later is called WSAPoll()
 */

#if defined(USE_WINSOCK) && (USE_WINSOCK > 1) && \
    defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
#  undef  HAVE_POLL
#  define HAVE_POLL 1
#  undef  HAVE_POLL_FINE
#  define HAVE_POLL_FINE 1
#  define poll(x,y,z) WSAPoll((x),(y),(z))
#  if defined(_MSC_VER) && defined(POLLRDNORM)
#    undef  POLLPRI
#    define POLLPRI POLLRDBAND
#    define HAVE_STRUCT_POLLFD 1
#  endif
#endif

/*
 * Definition of pollfd struct and constants for platforms lacking them.
 */

#if !defined(HAVE_STRUCT_POLLFD) && \
    !defined(HAVE_SYS_POLL_H) && \
    !defined(HAVE_POLL_H)

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

int Curl_socket_ready(curl_socket_t readfd, curl_socket_t writefd,
                      long timeout_ms);

int Curl_poll(struct pollfd ufds[], unsigned int nfds, int timeout_ms);

int Curl_wait_ms(int timeout_ms);

#ifdef TPF
int tpf_select_libcurl(int maxfds, fd_set* reads, fd_set* writes,
                       fd_set* excepts, struct timeval* tv);
#endif

/* Winsock and TPF sockets are not in range [0..FD_SETSIZE-1], which
   unfortunately makes it impossible for us to easily check if they're valid
*/
#if defined(USE_WINSOCK) || defined(TPF)
#define VALID_SOCK(x) 1
#define VERIFY_SOCK(x) Curl_nop_stmt
#else
#define VALID_SOCK(s) (((s) >= 0) && ((s) < FD_SETSIZE))
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(EINVAL); \
    return -1; \
  } \
} WHILE_FALSE
#endif

#endif /* __SELECT_H */
