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

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if !defined(HAVE_SELECT) && !defined(HAVE_POLL_FINE)
#error "We can't compile without select() or poll() support."
#endif

#ifdef __BEOS__
/* BeOS has FD_SET defined in socket.h */
#include <socket.h>
#endif

#ifdef MSDOS
#include <dos.h>  /* delay() */
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"

/* Winsock and TPF sockets are not in range [0..FD_SETSIZE-1] */

#if defined(USE_WINSOCK) || defined(TPF)
#define VERIFY_SOCK(x) do { } while (0)
#define VERIFY_NFDS(x) do { } while (0)
#else
#define VALID_SOCK(s) (((s) >= 0) && ((s) < FD_SETSIZE))
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(EINVAL); \
    return -1; \
  } \
} while(0)
#define VALID_NFDS(n) (((n) >= 0) && ((n) <= FD_SETSIZE))
#define VERIFY_NFDS(x) do { \
  if(!VALID_NFDS(x)) { \
    SET_SOCKERRNO(EINVAL); \
    return -1; \
  } \
} while(0)
#endif

/* Convenience local macros */

#define elapsed_ms  (int)curlx_tvdiff(curlx_tvnow(), initial_tv)

#ifdef CURL_ACKNOWLEDGE_EINTR
#define error_not_EINTR  (error != EINTR)
#else
#define error_not_EINTR  (1)
#endif

#define SMALL_POLLNFDS  0X20

/*
 * Internal function used for waiting a specific amount of ms
 * in Curl_socket_ready() and Curl_poll() when no file descriptor
 * is provided to wait on, just being used to delay execution.
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
#if !defined(MSDOS) && !defined(USE_WINSOCK)
#ifndef HAVE_POLL_FINE
  struct timeval pending_tv;
#endif
  struct timeval initial_tv;
  int pending_ms;
  int error;
#endif
  int r = 0;

  if (!timeout_ms)
    return 0;
  if (timeout_ms < 0) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }
#if defined(MSDOS)
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
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && error_not_EINTR &&
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
 *    CURL_CSELECT_IN | CURL_CSELECT_OUT | CURL_CSELECT_ERR
 */
int Curl_socket_ready(curl_socket_t readfd, curl_socket_t writefd,
                      int timeout_ms)
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
  int error;
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
    pfd[num].events = POLLRDNORM|POLLIN|POLLRDBAND|POLLPRI;
    pfd[num].revents = 0;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    pfd[num].fd = writefd;
    pfd[num].events = POLLWRNORM|POLLOUT;
    pfd[num].revents = 0;
    num++;
  }

  do {
    if (timeout_ms < 0)
      pending_ms = -1;
    r = poll(pfd, num, pending_ms);
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && error_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & (POLLRDNORM|POLLIN|POLLERR|POLLHUP))
      ret |= CURL_CSELECT_IN;
    if (pfd[num].revents & (POLLRDBAND|POLLPRI|POLLNVAL))
      ret |= CURL_CSELECT_ERR;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & (POLLWRNORM|POLLOUT))
      ret |= CURL_CSELECT_OUT;
    if (pfd[num].revents & (POLLERR|POLLHUP|POLLNVAL))
      ret |= CURL_CSELECT_ERR;
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
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && (error != EBADF) && error_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (FD_ISSET(readfd, &fds_read))
      ret |= CURL_CSELECT_IN;
    if (FD_ISSET(readfd, &fds_err))
      ret |= CURL_CSELECT_ERR;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (FD_ISSET(writefd, &fds_write))
      ret |= CURL_CSELECT_OUT;
    if (FD_ISSET(writefd, &fds_err))
      ret |= CURL_CSELECT_ERR;
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
  int error;
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
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && error_not_EINTR &&
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
    if (ufds[i].events & (POLLIN|POLLOUT|POLLPRI|
                          POLLRDNORM|POLLWRNORM|POLLRDBAND)) {
      if (ufds[i].fd > maxfd)
        maxfd = ufds[i].fd;
      if (ufds[i].events & (POLLRDNORM|POLLIN))
        FD_SET(ufds[i].fd, &fds_read);
      if (ufds[i].events & (POLLWRNORM|POLLOUT))
        FD_SET(ufds[i].fd, &fds_write);
      if (ufds[i].events & (POLLRDBAND|POLLPRI))
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
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && (error != EBADF) && error_not_EINTR &&
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
      ufds[i].revents |= POLLPRI;
    if (ufds[i].revents != 0)
      r++;
  }

#endif  /* HAVE_POLL_FINE */

  return r;
}

/*
 * This is a wrapper around select().  It uses poll() when a fine
 * poll() is available, in order to avoid limits with FD_SETSIZE,
 * otherwise select() is used.  An error is returned if select() is
 * being used and a the number of file descriptors is larger than
 * FD_SETSIZE.  A NULL timeout pointer makes this function wait
 * indefinitely, unles no valid file descriptor is given, when this
 * happens the NULL timeout is ignored and the function times out
 * immediately.  When compiled with CURL_ACKNOWLEDGE_EINTR defined,
 * EINTR condition is honored and function might exit early without
 * awaiting timeout, otherwise EINTR will be ignored.
 *
 * Return values:
 *   -1 = system call error or nfds > FD_SETSIZE
 *    0 = timeout
 *    N = number of file descriptors kept in file descriptor sets.
 */
int Curl_select(int nfds,
                fd_set *fds_read, fd_set *fds_write, fd_set *fds_excep,
                struct timeval *timeout)
{
  struct timeval initial_tv;
  int timeout_ms;
  int pending_ms;
  int error;
  int r;
#ifdef HAVE_POLL_FINE
  struct pollfd small_fds[SMALL_POLLNFDS];
  struct pollfd *poll_fds;
  int ix;
  int fd;
  int poll_nfds = 0;
#else
  struct timeval pending_tv;
  struct timeval *ptimeout;
#endif
  int ret = 0;

  if ((nfds < 0) ||
     ((nfds > 0) && (!fds_read && !fds_write && !fds_excep))) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }

  if (timeout) {
    if ((timeout->tv_sec < 0) ||
        (timeout->tv_usec < 0) ||
        (timeout->tv_usec >= 1000000)) {
      SET_SOCKERRNO(EINVAL);
      return -1;
    }
    timeout_ms = (int)(timeout->tv_sec * 1000) +
      (int)(timeout->tv_usec / 1000);
  }
  else {
    timeout_ms = -1;
  }

  if ((!nfds) || (!fds_read && !fds_write && !fds_excep)) {
    r = wait_ms(timeout_ms);
    return r;
  }

  pending_ms = timeout_ms;
  initial_tv = curlx_tvnow();

#ifdef HAVE_POLL_FINE

  if (fds_read || fds_write || fds_excep) {
    fd = nfds;
    while (fd--) {
      if ((fds_read && (0 != FD_ISSET(fd, fds_read))) ||
          (fds_write && (0 != FD_ISSET(fd, fds_write))) ||
          (fds_excep && (0 != FD_ISSET(fd, fds_excep))))
        poll_nfds++;
    }
  }

  if (!poll_nfds)
    poll_fds = NULL;
  else if (poll_nfds <= SMALL_POLLNFDS)
    poll_fds = small_fds;
  else {
    poll_fds = calloc((size_t)poll_nfds, sizeof(struct pollfd));
    if (!poll_fds) {
      SET_SOCKERRNO(ENOBUFS);
      return -1;
    }
  }

  if (poll_fds) {
    ix = 0;
    fd = nfds;
    while (fd--) {
      poll_fds[ix].events = 0;
      if (fds_read && (0 != FD_ISSET(fd, fds_read)))
        poll_fds[ix].events |= (POLLRDNORM|POLLIN);
      if (fds_write && (0 != FD_ISSET(fd, fds_write)))
        poll_fds[ix].events |= (POLLWRNORM|POLLOUT);
      if (fds_excep && (0 != FD_ISSET(fd, fds_excep)))
        poll_fds[ix].events |= (POLLRDBAND|POLLPRI);
      if (poll_fds[ix].events) {
        poll_fds[ix].fd = fd;
        poll_fds[ix].revents = 0;
        ix++;
      }
    }
  }

  do {
    if (timeout_ms < 0)
      pending_ms = -1;
    r = poll(poll_fds, poll_nfds, pending_ms);
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && error_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    ret = -1;

  if (r > 0) {
    ix = poll_nfds;
    while (ix--) {
      if (poll_fds[ix].revents & POLLNVAL) {
        SET_SOCKERRNO(EBADF);
        ret = -1;
        break;
      }
    }
  }

  if (!ret) {
    ix = poll_nfds;
    while (ix--) {
      if (fds_read && (0 != FD_ISSET(poll_fds[ix].fd, fds_read))) {
        if (0 == (poll_fds[ix].revents & (POLLRDNORM|POLLERR|POLLHUP|POLLIN)))
          FD_CLR(poll_fds[ix].fd, fds_read);
        else
          ret++;
      }
      if (fds_write && (0 != FD_ISSET(poll_fds[ix].fd, fds_write))) {
        if (0 == (poll_fds[ix].revents & (POLLWRNORM|POLLERR|POLLHUP|POLLOUT)))
          FD_CLR(poll_fds[ix].fd, fds_write);
        else
          ret++;
      }
      if (fds_excep && (0 != FD_ISSET(poll_fds[ix].fd, fds_excep))) {
        if (0 == (poll_fds[ix].revents & (POLLRDBAND|POLLERR|POLLHUP|POLLPRI)))
          FD_CLR(poll_fds[ix].fd, fds_excep);
        else
          ret++;
      }
    }
  }

  if (poll_fds && (poll_nfds > SMALL_POLLNFDS))
    free(poll_fds);

#else  /* HAVE_POLL_FINE */

  VERIFY_NFDS(nfds);

  ptimeout = (timeout_ms < 0) ? NULL : &pending_tv;

  do {
    if (ptimeout) {
      pending_tv.tv_sec = pending_ms / 1000;
      pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    }
    r = select(nfds, fds_read, fds_write, fds_excep, ptimeout);
  } while ((r == -1) && (error = SOCKERRNO) &&
           (error != EINVAL) && (error != EBADF) && error_not_EINTR &&
           ((timeout_ms < 0) || ((pending_ms = timeout_ms - elapsed_ms) > 0)));

  if (r < 0)
    ret = -1;
  else
    ret = r;

#endif  /* HAVE_POLL_FINE */

  return ret;
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
