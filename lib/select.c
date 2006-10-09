/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
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

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"

#if defined(WIN32) || defined(TPF)
#define VERIFY_SOCK(x)  /* sockets are not in range [0..FD_SETSIZE] */
#else
#define VALID_SOCK(s) (((s) >= 0) && ((s) < FD_SETSIZE))
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    errno = EINVAL; \
    return -1; \
  } \
} while(0)
#endif

/*
 * This is an internal function used for waiting for read or write
 * events on single file descriptors.  It attempts to replace select()
 * in order to avoid limits with FD_SETSIZE.
 *
 * Return values:
 *   -1 = system call error
 *    0 = timeout
 *    CSELECT_IN | CSELECT_OUT | CSELECT_ERR
 */
int Curl_select(curl_socket_t readfd, curl_socket_t writefd, int timeout_ms)
{
#if defined(HAVE_POLL_FINE) || defined(CURL_HAVE_WSAPOLL)
  struct pollfd pfd[2];
  int num;
  int r;
  int ret;

  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    pfd[num].fd = readfd;
    pfd[num].events = POLLIN;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    pfd[num].fd = writefd;
    pfd[num].events = POLLOUT;
    num++;
  }

#ifdef HAVE_POLL_FINE
  do {
    r = poll(pfd, num, timeout_ms);
  } while((r == -1) && (errno == EINTR));
#else
  r = WSAPoll(pfd, num, timeout_ms);
#endif

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
      if (errno == EINPROGRESS)
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
    if (pfd[num].revents & POLLERR)
      ret |= CSELECT_ERR;
  }

  return ret;
#else
  struct timeval timeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
  int r;
  int ret;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

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

  do {
    r = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, &timeout);
  } while((r == -1) && (Curl_sockerrno() == EINTR));

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
#endif
}

/*
 * This is a wrapper around poll().  If poll() does not exist, then
 * select() is used instead.  An error is returned if select() is
 * being used and a file descriptor too large for FD_SETSIZE.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    1 = number of structures with non zero revent fields
 */
int Curl_poll(struct pollfd ufds[], unsigned int nfds, int timeout_ms)
{
  int r;
#ifdef HAVE_POLL_FINE
  do {
    r = poll(ufds, nfds, timeout_ms);
  } while((r == -1) && (errno == EINTR));
#elif defined(CURL_HAVE_WSAPOLL)
  r = WSAPoll(ufds, nfds, timeout_ms);
#else
  struct timeval timeout;
  struct timeval *ptimeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
  unsigned int i;

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);
  maxfd = (curl_socket_t)-1;

  for (i = 0; i < nfds; i++) {
    if (ufds[i].fd == CURL_SOCKET_BAD)
      continue;
#ifndef WIN32  /* This is harmless and wrong on Win32 */
    if (ufds[i].fd >= FD_SETSIZE) {
      errno = EINVAL;
      return -1;
    }
#endif
    if (ufds[i].fd > maxfd)
      maxfd = ufds[i].fd;
    if (ufds[i].events & POLLIN)
      FD_SET(ufds[i].fd, &fds_read);
    if (ufds[i].events & POLLOUT)
      FD_SET(ufds[i].fd, &fds_write);
    if (ufds[i].events & POLLERR)
      FD_SET(ufds[i].fd, &fds_err);
  }

  if (timeout_ms < 0) {
    ptimeout = NULL;      /* wait forever */
  } else {
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    ptimeout = &timeout;
  }

  do {
    r = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, ptimeout);
  } while((r == -1) && (Curl_sockerrno() == EINTR));

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
#endif
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
