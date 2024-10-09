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

#if !defined(HAVE_SELECT) && !defined(HAVE_POLL)
#error "We cannot compile without select() or poll() support."
#endif

#include <limits.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifdef MSDOS
#include <dos.h>  /* delay() */
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"
#include "timediff.h"
#include "warnless.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Internal function used for waiting a specific amount of ms in
 * Curl_socket_check() and Curl_poll() when no file descriptor is provided to
 * wait on, just being used to delay execution. Winsock select() and poll()
 * timeout mechanisms need a valid socket descriptor in a not null file
 * descriptor set to work. Waiting indefinitely with this function is not
 * allowed, a zero or negative timeout value will return immediately. Timeout
 * resolution, accuracy, as well as maximum supported value is system
 * dependent, neither factor is a critical issue for the intended use of this
 * function in the library.
 *
 * Return values:
 *   -1 = system call error, or invalid timeout value
 *    0 = specified timeout has elapsed, or interrupted
 */
int Curl_wait_ms(timediff_t timeout_ms)
{
  int r = 0;

  if(!timeout_ms)
    return 0;
  if(timeout_ms < 0) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }
#if defined(MSDOS)
  delay(timeout_ms);
#elif defined(_WIN32)
  /* prevent overflow, timeout_ms is typecast to ULONG/DWORD. */
#if TIMEDIFF_T_MAX >= ULONG_MAX
  if(timeout_ms >= ULONG_MAX)
    timeout_ms = ULONG_MAX-1;
    /* do not use ULONG_MAX, because that is equal to INFINITE */
#endif
  Sleep((ULONG)timeout_ms);
#else
  /* avoid using poll() for this since it behaves incorrectly with no sockets
     on Apple operating systems */
  {
    struct timeval pending_tv;
    r = select(0, NULL, NULL, NULL, curlx_mstotv(&pending_tv, timeout_ms));
  }
#endif /* _WIN32 */
  if(r) {
    if((r == -1) && (SOCKERRNO == EINTR))
      /* make EINTR from select or poll not a "lethal" error */
      r = 0;
    else
      r = -1;
  }
  return r;
}

#ifndef HAVE_POLL
/*
 * This is a wrapper around select() to aid in Windows compatibility. A
 * negative timeout value makes this function wait indefinitely, unless no
 * valid file descriptor is given, when this happens the negative timeout is
 * ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    N = number of signalled file descriptors
 */
static int our_select(curl_socket_t maxfd,   /* highest socket number */
                      fd_set *fds_read,      /* sockets ready for reading */
                      fd_set *fds_write,     /* sockets ready for writing */
                      fd_set *fds_err,       /* sockets with errors */
                      timediff_t timeout_ms) /* milliseconds to wait */
{
  struct timeval pending_tv;
  struct timeval *ptimeout;

#ifdef USE_WINSOCK
  /* Winsock select() cannot handle zero events. See the comment below. */
  if((!fds_read || fds_read->fd_count == 0) &&
     (!fds_write || fds_write->fd_count == 0) &&
     (!fds_err || fds_err->fd_count == 0)) {
    /* no sockets, just wait */
    return Curl_wait_ms(timeout_ms);
  }
#endif

  ptimeout = curlx_mstotv(&pending_tv, timeout_ms);

#ifdef USE_WINSOCK
  /* Winsock select() must not be called with an fd_set that contains zero
    fd flags, or it will return WSAEINVAL. But, it also cannot be called
    with no fd_sets at all!  From the documentation:

    Any two of the parameters, readfds, writefds, or exceptfds, can be
    given as null. At least one must be non-null, and any non-null
    descriptor set must contain at least one handle to a socket.

    It is unclear why Winsock does not just handle this for us instead of
    calling this an error. Luckily, with Winsock, we can _also_ ask how
    many bits are set on an fd_set. So, let's just check it beforehand.
  */
  return select((int)maxfd + 1,
                fds_read && fds_read->fd_count ? fds_read : NULL,
                fds_write && fds_write->fd_count ? fds_write : NULL,
                fds_err && fds_err->fd_count ? fds_err : NULL, ptimeout);
#else
  return select((int)maxfd + 1, fds_read, fds_write, fds_err, ptimeout);
#endif
}

#endif

/*
 * Wait for read or write events on a set of file descriptors. It uses poll()
 * when poll() is available, in order to avoid limits with FD_SETSIZE,
 * otherwise select() is used. An error is returned if select() is being used
 * and a file descriptor is too large for FD_SETSIZE.
 *
 * A negative timeout value makes this function wait indefinitely, unless no
 * valid file descriptor is given, when this happens the negative timeout is
 * ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    [bitmask] = action as described below
 *
 * CURL_CSELECT_IN - first socket is readable
 * CURL_CSELECT_IN2 - second socket is readable
 * CURL_CSELECT_OUT - write socket is writable
 * CURL_CSELECT_ERR - an error condition occurred
 */
int Curl_socket_check(curl_socket_t readfd0, /* two sockets to read from */
                      curl_socket_t readfd1,
                      curl_socket_t writefd, /* socket to write to */
                      timediff_t timeout_ms) /* milliseconds to wait */
{
  struct pollfd pfd[3];
  int num;
  int r;

  if((readfd0 == CURL_SOCKET_BAD) && (readfd1 == CURL_SOCKET_BAD) &&
     (writefd == CURL_SOCKET_BAD)) {
    /* no sockets, just wait */
    return Curl_wait_ms(timeout_ms);
  }

  /* Avoid initial timestamp, avoid Curl_now() call, when elapsed
     time in this function does not need to be measured. This happens
     when function is called with a zero timeout or a negative timeout
     value indicating a blocking call should be performed. */

  num = 0;
  if(readfd0 != CURL_SOCKET_BAD) {
    pfd[num].fd = readfd0;
    pfd[num].events = POLLRDNORM|POLLIN|POLLRDBAND|POLLPRI;
    pfd[num].revents = 0;
    num++;
  }
  if(readfd1 != CURL_SOCKET_BAD) {
    pfd[num].fd = readfd1;
    pfd[num].events = POLLRDNORM|POLLIN|POLLRDBAND|POLLPRI;
    pfd[num].revents = 0;
    num++;
  }
  if(writefd != CURL_SOCKET_BAD) {
    pfd[num].fd = writefd;
    pfd[num].events = POLLWRNORM|POLLOUT|POLLPRI;
    pfd[num].revents = 0;
    num++;
  }

  r = Curl_poll(pfd, (unsigned int)num, timeout_ms);
  if(r <= 0)
    return r;

  r = 0;
  num = 0;
  if(readfd0 != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLRDNORM|POLLIN|POLLERR|POLLHUP))
      r |= CURL_CSELECT_IN;
    if(pfd[num].revents & (POLLPRI|POLLNVAL))
      r |= CURL_CSELECT_ERR;
    num++;
  }
  if(readfd1 != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLRDNORM|POLLIN|POLLERR|POLLHUP))
      r |= CURL_CSELECT_IN2;
    if(pfd[num].revents & (POLLPRI|POLLNVAL))
      r |= CURL_CSELECT_ERR;
    num++;
  }
  if(writefd != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLWRNORM|POLLOUT))
      r |= CURL_CSELECT_OUT;
    if(pfd[num].revents & (POLLERR|POLLHUP|POLLPRI|POLLNVAL))
      r |= CURL_CSELECT_ERR;
  }

  return r;
}

/*
 * This is a wrapper around poll(). If poll() does not exist, then
 * select() is used instead. An error is returned if select() is
 * being used and a file descriptor is too large for FD_SETSIZE.
 * A negative timeout value makes this function wait indefinitely,
 * unless no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    N = number of structures with non zero revent fields
 */
int Curl_poll(struct pollfd ufds[], unsigned int nfds, timediff_t timeout_ms)
{
#ifdef HAVE_POLL
  int pending_ms;
#else
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
#endif
  bool fds_none = TRUE;
  unsigned int i;
  int r;

  if(ufds) {
    for(i = 0; i < nfds; i++) {
      if(ufds[i].fd != CURL_SOCKET_BAD) {
        fds_none = FALSE;
        break;
      }
    }
  }
  if(fds_none) {
    /* no sockets, just wait */
    return Curl_wait_ms(timeout_ms);
  }

  /* Avoid initial timestamp, avoid Curl_now() call, when elapsed
     time in this function does not need to be measured. This happens
     when function is called with a zero timeout or a negative timeout
     value indicating a blocking call should be performed. */

#ifdef HAVE_POLL

  /* prevent overflow, timeout_ms is typecast to int. */
#if TIMEDIFF_T_MAX > INT_MAX
  if(timeout_ms > INT_MAX)
    timeout_ms = INT_MAX;
#endif
  if(timeout_ms > 0)
    pending_ms = (int)timeout_ms;
  else if(timeout_ms < 0)
    pending_ms = -1;
  else
    pending_ms = 0;
  r = poll(ufds, nfds, pending_ms);
  if(r <= 0) {
    if((r == -1) && (SOCKERRNO == EINTR))
      /* make EINTR from select or poll not a "lethal" error */
      r = 0;
    return r;
  }

  for(i = 0; i < nfds; i++) {
    if(ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    if(ufds[i].revents & POLLHUP)
      ufds[i].revents |= POLLIN;
    if(ufds[i].revents & POLLERR)
      ufds[i].revents |= POLLIN|POLLOUT;
  }

#else  /* HAVE_POLL */

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);
  maxfd = (curl_socket_t)-1;

  for(i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if(ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    VERIFY_SOCK(ufds[i].fd);
    if(ufds[i].events & (POLLIN|POLLOUT|POLLPRI|
                         POLLRDNORM|POLLWRNORM|POLLRDBAND)) {
      if(ufds[i].fd > maxfd)
        maxfd = ufds[i].fd;
      if(ufds[i].events & (POLLRDNORM|POLLIN))
        FD_SET(ufds[i].fd, &fds_read);
      if(ufds[i].events & (POLLWRNORM|POLLOUT))
        FD_SET(ufds[i].fd, &fds_write);
      if(ufds[i].events & (POLLRDBAND|POLLPRI))
        FD_SET(ufds[i].fd, &fds_err);
    }
  }

  /*
     Note also that Winsock ignores the first argument, so we do not worry
     about the fact that maxfd is computed incorrectly with Winsock (since
     curl_socket_t is unsigned in such cases and thus -1 is the largest
     value).
  */
  r = our_select(maxfd, &fds_read, &fds_write, &fds_err, timeout_ms);
  if(r <= 0) {
    if((r == -1) && (SOCKERRNO == EINTR))
      /* make EINTR from select or poll not a "lethal" error */
      r = 0;
    return r;
  }

  r = 0;
  for(i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if(ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    if(FD_ISSET(ufds[i].fd, &fds_read)) {
      if(ufds[i].events & POLLRDNORM)
        ufds[i].revents |= POLLRDNORM;
      if(ufds[i].events & POLLIN)
        ufds[i].revents |= POLLIN;
    }
    if(FD_ISSET(ufds[i].fd, &fds_write)) {
      if(ufds[i].events & POLLWRNORM)
        ufds[i].revents |= POLLWRNORM;
      if(ufds[i].events & POLLOUT)
        ufds[i].revents |= POLLOUT;
    }
    if(FD_ISSET(ufds[i].fd, &fds_err)) {
      if(ufds[i].events & POLLRDBAND)
        ufds[i].revents |= POLLRDBAND;
      if(ufds[i].events & POLLPRI)
        ufds[i].revents |= POLLPRI;
    }
    if(ufds[i].revents)
      r++;
  }

#endif  /* HAVE_POLL */

  return r;
}

void Curl_pollfds_init(struct curl_pollfds *cpfds,
                       struct pollfd *static_pfds,
                       unsigned int static_count)
{
  DEBUGASSERT(cpfds);
  memset(cpfds, 0, sizeof(*cpfds));
  if(static_pfds && static_count) {
    cpfds->pfds = static_pfds;
    cpfds->count = static_count;
  }
}

void Curl_pollfds_cleanup(struct curl_pollfds *cpfds)
{
  DEBUGASSERT(cpfds);
  if(cpfds->allocated_pfds) {
    free(cpfds->pfds);
  }
  memset(cpfds, 0, sizeof(*cpfds));
}

static CURLcode cpfds_increase(struct curl_pollfds *cpfds, unsigned int inc)
{
  struct pollfd *new_fds;
  unsigned int new_count = cpfds->count + inc;

  new_fds = calloc(new_count, sizeof(struct pollfd));
  if(!new_fds)
    return CURLE_OUT_OF_MEMORY;

  memcpy(new_fds, cpfds->pfds, cpfds->count * sizeof(struct pollfd));
  if(cpfds->allocated_pfds)
    free(cpfds->pfds);
  cpfds->pfds = new_fds;
  cpfds->count = new_count;
  cpfds->allocated_pfds = TRUE;
  return CURLE_OK;
}

static CURLcode cpfds_add_sock(struct curl_pollfds *cpfds,
                               curl_socket_t sock, short events, bool fold)
{
  int i;

  if(fold && cpfds->n <= INT_MAX) {
    for(i = (int)cpfds->n - 1; i >= 0; --i) {
      if(sock == cpfds->pfds[i].fd) {
        cpfds->pfds[i].events |= events;
        return CURLE_OK;
      }
    }
  }
  /* not folded, add new entry */
  if(cpfds->n >= cpfds->count) {
    if(cpfds_increase(cpfds, 100))
      return CURLE_OUT_OF_MEMORY;
  }
  cpfds->pfds[cpfds->n].fd = sock;
  cpfds->pfds[cpfds->n].events = events;
  ++cpfds->n;
  return CURLE_OK;
}

CURLcode Curl_pollfds_add_sock(struct curl_pollfds *cpfds,
                               curl_socket_t sock, short events)
{
  return cpfds_add_sock(cpfds, sock, events, FALSE);
}

CURLcode Curl_pollfds_add_ps(struct curl_pollfds *cpfds,
                             struct easy_pollset *ps)
{
  size_t i;

  DEBUGASSERT(cpfds);
  DEBUGASSERT(ps);
  for(i = 0; i < ps->num; i++) {
    short events = 0;
    if(ps->actions[i] & CURL_POLL_IN)
      events |= POLLIN;
    if(ps->actions[i] & CURL_POLL_OUT)
      events |= POLLOUT;
    if(events) {
      if(cpfds_add_sock(cpfds, ps->sockets[i], events, TRUE))
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

void Curl_waitfds_init(struct curl_waitfds *cwfds,
                       struct curl_waitfd *static_wfds,
                       unsigned int static_count)
{
  DEBUGASSERT(cwfds);
  DEBUGASSERT(static_wfds);
  memset(cwfds, 0, sizeof(*cwfds));
  cwfds->wfds = static_wfds;
  cwfds->count = static_count;
}

static CURLcode cwfds_add_sock(struct curl_waitfds *cwfds,
                               curl_socket_t sock, short events)
{
  int i;

  if(cwfds->n <= INT_MAX) {
    for(i = (int)cwfds->n - 1; i >= 0; --i) {
      if(sock == cwfds->wfds[i].fd) {
        cwfds->wfds[i].events |= events;
        return CURLE_OK;
      }
    }
  }
  /* not folded, add new entry */
  if(cwfds->n >= cwfds->count)
    return CURLE_OUT_OF_MEMORY;
  cwfds->wfds[cwfds->n].fd = sock;
  cwfds->wfds[cwfds->n].events = events;
  ++cwfds->n;
  return CURLE_OK;
}

CURLcode Curl_waitfds_add_ps(struct curl_waitfds *cwfds,
                             struct easy_pollset *ps)
{
  size_t i;

  DEBUGASSERT(cwfds);
  DEBUGASSERT(ps);
  for(i = 0; i < ps->num; i++) {
    short events = 0;
    if(ps->actions[i] & CURL_POLL_IN)
      events |= CURL_WAIT_POLLIN;
    if(ps->actions[i] & CURL_POLL_OUT)
      events |= CURL_WAIT_POLLOUT;
    if(events) {
      if(cwfds_add_sock(cwfds, ps->sockets[i], events))
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}
