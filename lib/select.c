/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <errno.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif

#ifdef __BEOS__
/* BeOS has FD_SET defined in socket.h */
#include <socket.h>
#endif

#ifdef __MSDOS__
#include <dos.h>  /* delay() */
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"

#ifdef USE_WINSOCK
#  undef  EINTR
#  define EINTR  WSAEINTR
#  undef  EINVAL
#  define EINVAL WSAEINVAL
#endif

/* Winsock and TPF sockets are not in range [0..FD_SETSIZE-1] */

#if defined(USE_WINSOCK) || defined(TPF)
#define VERIFY_SOCK(x) do { } while (0)
#else
#define VALID_SOCK(s) (((s) >= 0) && ((s) < FD_SETSIZE))
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(EINVAL); \
    return -1; \
  } \
} while(0)
#endif

/* Convenience local macros */

#define elapsed_ms  (int)curlx_tvdiff(curlx_tvnow(), initial_tv)

#ifdef CURL_ACKNOWLEDGE_EINTR
#define sockerrno_not_EINTR  (SOCKERRNO != EINTR)
#else
#define sockerrno_not_EINTR  (1)
#endif

/*
 * Internal function used for waiting a specific amount of ms
 * in Curl_select() and Curl_poll() when no file descriptor is
 * provided to wait on, just being used to delay execution.
 * WinSock select() and poll() timeout mechanisms need a valid
 * socket descriptor in a not null file descriptor set to work.
 * Waiting indefinitely with this function is not allowed, a
 * zero or negative timeout value will return immediately.
 * Timeout resolution, accuracy, as well as maximum supported
 * value is system dependant, neither factor is a citical issue
 * for the intended use of this function in the library.
 * On non-DOS and non-Winsock platforms, when compiled with
 * CURL_ACKNOWLEDGE_EINTR defined, EINTR condition is honored
 * and function might exit early without awaiting full timeout,
 * otherwise EINTR will be ignored and full timeout will elapse.
 *
 * Return values:
 *   -1 = system call error, invalid timeout value, or interrupted
 *    0 = specified timeout has elapsed
 */
static int wait_ms(int timeout_ms)
{
#if !defined(__MSDOS__) && !defined(USE_WINSOCK)
#ifndef HAVE_POLL_FINE
  struct timeval pending_tv;
#endif
  struct timeval initial_tv;
  int pending_ms;
#endif
  int r = 0;

  if (!timeout_ms)
    return 0;
  if (timeout_ms < 0) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }
#if defined(__MSDOS__)
  delay(timeout_ms);
#elif defined(USE_WINSOCK)
  Sleep(timeout_ms);
#else
  pending_ms = timeout_ms;
  initial_tv = curlx_tvnow();
  do {
#if defined(HAVE_POLL_FINE)
    r = poll(NULL, 0, pending_ms);
#else
    pending_tv.tv_sec = pending_ms / 1000;
    pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    r = select(0, NULL, NULL, NULL, &pending_tv);
#endif /* HAVE_POLL_FINE */
  } while ((r == -1) && (SOCKERRNO != EINVAL) && sockerrno_not_EINTR &&
           ((pending_ms = timeout_ms - elapsed_ms) > 0));
#endif /* USE_WINSOCK */
  if (r)
    r = -1;
  return r;
}

/*
 * This is an internal function used for waiting for read or write
 * events on a pair of file descriptors.  It uses poll() when a fine
 * poll() is available, in order to avoid limits with FD_SETSIZE,
 * otherwise select() is used.  An error is returned if select() is
 * being used and a file descriptor is too large for FD_SETSIZE.
 * A negative timeout value makes this function wait indefinitely,
 * unles no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 * When compiled with CURL_ACKNOWLEDGE_EINTR defined, EINTR condition
 * is honored and function might exit early without awaiting timeout,
 * otherwise EINTR will be ignored.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    CSELECT_IN | CSELECT_OUT | CSELECT_ERR
 */
int Curl_select(curl_socket_t readfd, curl_socket_t writefd, int timeout_ms)
{
#ifdef HAVE_POLL_FINE
  struct pollfd pfd[2];
  int num;
#else
  struct timeval pending_tv;
  struct timeval *ptimeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
#endif
  struct timeval initial_tv;
  int pending_ms;
  int r;
  int ret;

  if((readfd == CURL_SOCKET_BAD) && (writefd == CURL_SOCKET_BAD)) {
    r = wait_ms(timeout_ms);
    return r;
  }

  pending_ms = timeout_ms;
  initial_tv = curlx_tvnow();

#ifdef HAVE_POLL_FINE

  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    pfd[num].fd = readfd;
    pfd[num].events = POLLIN;
    pfd[num].revents = 0;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    pfd[num].fd = writefd;
    pfd[num].events = POLLOUT;
    pfd[num].revents = 0;
    num++;
  }

  do {
    if (timeout_ms < 0)
      pending_ms = -1;
    r = poll(pfd, num, pending_ms);
  } while ((r == -1) && (SOCKERRNO != EINVAL) && sockerrno_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & (POLLIN|POLLHUP))
      ret |= CSELECT_IN;
    if (pfd[num].revents & POLLERR) {
#ifdef __CYGWIN__
      /* Cygwin 1.5.21 needs this hack to pass test 160 */
      if (ERRNO == EINPROGRESS)
        ret |= CSELECT_IN;
      else
#endif
        ret |= CSELECT_ERR;
    }
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & POLLOUT)
      ret |= CSELECT_OUT;
    if (pfd[num].revents & (POLLERR|POLLHUP))
      ret |= CSELECT_ERR;
  }

  return ret;

#else  /* HAVE_POLL_FINE */

  FD_ZERO(&fds_err);
  maxfd = (curl_socket_t)-1;

  FD_ZERO(&fds_read);
  if (readfd != CURL_SOCKET_BAD) {
    VERIFY_SOCK(readfd);
    FD_SET(readfd, &fds_read);
    FD_SET(readfd, &fds_err);
    maxfd = readfd;
  }

  FD_ZERO(&fds_write);
  if (writefd != CURL_SOCKET_BAD) {
    VERIFY_SOCK(writefd);
    FD_SET(writefd, &fds_write);
    FD_SET(writefd, &fds_err);
    if (writefd > maxfd)
      maxfd = writefd;
  }

  ptimeout = (timeout_ms < 0) ? NULL : &pending_tv;

  do {
    if (ptimeout) {
      pending_tv.tv_sec = pending_ms / 1000;
      pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    }
    r = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, ptimeout);
  } while ((r == -1) && (SOCKERRNO != EINVAL) && sockerrno_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (FD_ISSET(readfd, &fds_read))
      ret |= CSELECT_IN;
    if (FD_ISSET(readfd, &fds_err))
      ret |= CSELECT_ERR;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (FD_ISSET(writefd, &fds_write))
      ret |= CSELECT_OUT;
    if (FD_ISSET(writefd, &fds_err))
      ret |= CSELECT_ERR;
  }

  return ret;

#endif  /* HAVE_POLL_FINE */

}

/*
 * This is a wrapper around poll().  If poll() does not exist, then
 * select() is used instead.  An error is returned if select() is
 * being used and a file descriptor is too large for FD_SETSIZE.
 * A negative timeout value makes this function wait indefinitely,
 * unles no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 * When compiled with CURL_ACKNOWLEDGE_EINTR defined, EINTR condition
 * is honored and function might exit early without awaiting timeout,
 * otherwise EINTR will be ignored.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    N = number of structures with non zero revent fields
 */
int Curl_poll(struct pollfd ufds[], unsigned int nfds, int timeout_ms)
{
#ifndef HAVE_POLL_FINE
  struct timeval pending_tv;
  struct timeval *ptimeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
#endif
  struct timeval initial_tv;
  bool fds_none = TRUE;
  unsigned int i;
  int pending_ms;
  int r;

  if (ufds) {
    for (i = 0; i < nfds; i++) {
      if (ufds[i].fd != CURL_SOCKET_BAD) {
        fds_none = FALSE;
        break;
      }
    }
  }
  if (fds_none) {
    r = wait_ms(timeout_ms);
    return r;
  }

  pending_ms = timeout_ms;
  initial_tv = curlx_tvnow();

#ifdef HAVE_POLL_FINE

  do {
    if (timeout_ms < 0)
      pending_ms = -1;
    r = poll(ufds, nfds, pending_ms);
  } while ((r == -1) && (SOCKERRNO != EINVAL) && sockerrno_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

#else  /* HAVE_POLL_FINE */

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);
  maxfd = (curl_socket_t)-1;

  for (i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if (ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    VERIFY_SOCK(ufds[i].fd);
    if (ufds[i].events & (POLLIN|POLLOUT|POLLERR)) {
      if (ufds[i].fd > maxfd)
        maxfd = ufds[i].fd;
      if (ufds[i].events & POLLIN)
        FD_SET(ufds[i].fd, &fds_read);
      if (ufds[i].events & POLLOUT)
        FD_SET(ufds[i].fd, &fds_write);
      if (ufds[i].events & POLLERR)
        FD_SET(ufds[i].fd, &fds_err);
    }
  }

  ptimeout = (timeout_ms < 0) ? NULL : &pending_tv;

  do {
    if (ptimeout) {
      pending_tv.tv_sec = pending_ms / 1000;
      pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    }
    r = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, ptimeout);
  } while ((r == -1) && (SOCKERRNO != EINVAL) && sockerrno_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  r = 0;
  for (i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if (ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    if (FD_ISSET(ufds[i].fd, &fds_read))
      ufds[i].revents |= POLLIN;
    if (FD_ISSET(ufds[i].fd, &fds_write))
      ufds[i].revents |= POLLOUT;
    if (FD_ISSET(ufds[i].fd, &fds_err))
      ufds[i].revents |= POLLERR;
    if (ufds[i].revents != 0)
      r++;
  }

#endif  /* HAVE_POLL_FINE */

  return r;
}

#ifdef TPF
/*
 * This is a replacement for select() on the TPF platform.
 * It is used whenever libcurl calls select().
 * The call below to tpf_process_signals() is required because
 * TPF's select calls are not signal interruptible.
 *
 * Return values are the same as select's.
 */
int tpf_select_libcurl(int maxfds, fd_set* reads, fd_set* writes,
                       fd_set* excepts, struct timeval* tv)
{
   int rc;

   rc = tpf_select_bsd(maxfds, reads, writes, excepts, tv);
   tpf_process_signals();
   return(rc);
}
#endif /* TPF */
