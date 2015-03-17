/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if !defined(HAVE_SELECT) && !defined(HAVE_POLL_FINE)
#error "We can't compile without select() or poll() support."
#endif

#if defined(__BEOS__) && !defined(__HAIKU__)
/* BeOS has FD_SET defined in socket.h */
#include <socket.h>
#endif

#ifdef MSDOS
#include <dos.h>  /* delay() */
#endif

#ifdef __VXWORKS__
#include <strings.h>  /* bzero() in FD_SET */
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"
#include "warnless.h"

/* Convenience local macros */

#define elapsed_ms  (int)curlx_tvdiff(curlx_tvnow(), initial_tv)

int Curl_ack_eintr = 0;
#define error_not_EINTR (Curl_ack_eintr || error != EINTR)

/*
 * Internal function used for waiting a specific amount of ms
 * in Curl_socket_ready() and Curl_poll() when no file descriptor
 * is provided to wait on, just being used to delay execution.
 * WinSock select() and poll() timeout mechanisms need a valid
 * socket descriptor in a not null file descriptor set to work.
 * Waiting indefinitely with this function is not allowed, a
 * zero or negative timeout value will return immediately.
 * Timeout resolution, accuracy, as well as maximum supported
 * value is system dependent, neither factor is a citical issue
 * for the intended use of this function in the library.
 *
 * Return values:
 *   -1 = system call error, invalid timeout value, or interrupted
 *    0 = specified timeout has elapsed
 */
int Curl_wait_ms(int timeout_ms)
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

  if(!timeout_ms)
    return 0;
  if(timeout_ms < 0) {
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
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && error_not_EINTR)
      break;
    pending_ms = timeout_ms - elapsed_ms;
    if(pending_ms <= 0) {
      r = 0;  /* Simulate a "call timed out" case */
      break;
    }
  } while(r == -1);
#endif /* USE_WINSOCK */
  if(r)
    r = -1;
  return r;
}

/*
 * Wait for read or write events on a set of file descriptors. It uses poll()
 * when a fine poll() is available, in order to avoid limits with FD_SETSIZE,
 * otherwise select() is used.  An error is returned if select() is being used
 * and a file descriptor is too large for FD_SETSIZE.
 *
 * A negative timeout value makes this function wait indefinitely,
 * unles no valid file descriptor is given, when this happens the
 * negative timeout is ignored and the function times out immediately.
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
                      long timeout_ms)       /* milliseconds to wait */
{
#ifdef HAVE_POLL_FINE
  struct pollfd pfd[3];
  int num;
#else
  struct timeval pending_tv;
  struct timeval *ptimeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
#endif
  struct timeval initial_tv = {0, 0};
  int pending_ms = 0;
  int error;
  int r;
  int ret;

  if((readfd0 == CURL_SOCKET_BAD) && (readfd1 == CURL_SOCKET_BAD) &&
     (writefd == CURL_SOCKET_BAD)) {
    /* no sockets, just wait */
    r = Curl_wait_ms((int)timeout_ms);
    return r;
  }

  /* Avoid initial timestamp, avoid curlx_tvnow() call, when elapsed
     time in this function does not need to be measured. This happens
     when function is called with a zero timeout or a negative timeout
     value indicating a blocking call should be performed. */

  if(timeout_ms > 0) {
    pending_ms = (int)timeout_ms;
    initial_tv = curlx_tvnow();
  }

#ifdef HAVE_POLL_FINE

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
    pfd[num].events = POLLWRNORM|POLLOUT;
    pfd[num].revents = 0;
    num++;
  }

  do {
    if(timeout_ms < 0)
      pending_ms = -1;
    else if(!timeout_ms)
      pending_ms = 0;
    r = poll(pfd, num, pending_ms);
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && error_not_EINTR)
      break;
    if(timeout_ms > 0) {
      pending_ms = (int)(timeout_ms - elapsed_ms);
      if(pending_ms <= 0) {
        r = 0;  /* Simulate a "call timed out" case */
        break;
      }
    }
  } while(r == -1);

  if(r < 0)
    return -1;
  if(r == 0)
    return 0;

  ret = 0;
  num = 0;
  if(readfd0 != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLRDNORM|POLLIN|POLLERR|POLLHUP))
      ret |= CURL_CSELECT_IN;
    if(pfd[num].revents & (POLLRDBAND|POLLPRI|POLLNVAL))
      ret |= CURL_CSELECT_ERR;
    num++;
  }
  if(readfd1 != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLRDNORM|POLLIN|POLLERR|POLLHUP))
      ret |= CURL_CSELECT_IN2;
    if(pfd[num].revents & (POLLRDBAND|POLLPRI|POLLNVAL))
      ret |= CURL_CSELECT_ERR;
    num++;
  }
  if(writefd != CURL_SOCKET_BAD) {
    if(pfd[num].revents & (POLLWRNORM|POLLOUT))
      ret |= CURL_CSELECT_OUT;
    if(pfd[num].revents & (POLLERR|POLLHUP|POLLNVAL))
      ret |= CURL_CSELECT_ERR;
  }

  return ret;

#else  /* HAVE_POLL_FINE */

  FD_ZERO(&fds_err);
  maxfd = (curl_socket_t)-1;

  FD_ZERO(&fds_read);
  if(readfd0 != CURL_SOCKET_BAD) {
    VERIFY_SOCK(readfd0);
    FD_SET(readfd0, &fds_read);
    FD_SET(readfd0, &fds_err);
    maxfd = readfd0;
  }
  if(readfd1 != CURL_SOCKET_BAD) {
    VERIFY_SOCK(readfd1);
    FD_SET(readfd1, &fds_read);
    FD_SET(readfd1, &fds_err);
    if(readfd1 > maxfd)
      maxfd = readfd1;
  }

  FD_ZERO(&fds_write);
  if(writefd != CURL_SOCKET_BAD) {
    VERIFY_SOCK(writefd);
    FD_SET(writefd, &fds_write);
    FD_SET(writefd, &fds_err);
    if(writefd > maxfd)
      maxfd = writefd;
  }

  ptimeout = (timeout_ms < 0) ? NULL : &pending_tv;

  do {
    if(timeout_ms > 0) {
      pending_tv.tv_sec = pending_ms / 1000;
      pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    }
    else if(!timeout_ms) {
      pending_tv.tv_sec = 0;
      pending_tv.tv_usec = 0;
    }

    /* WinSock select() must not be called with an fd_set that contains zero
       fd flags, or it will return WSAEINVAL.  But, it also can't be called
       with no fd_sets at all!  From the documentation:

         Any two of the parameters, readfds, writefds, or exceptfds, can be
         given as null. At least one must be non-null, and any non-null
         descriptor set must contain at least one handle to a socket.

       We know that we have at least one bit set in at least two fd_sets in
       this case, but we may have no bits set in either fds_read or fd_write,
       so check for that and handle it.  Luckily, with WinSock, we can _also_
       ask how many bits are set on an fd_set.

       It is unclear why WinSock doesn't just handle this for us instead of
       calling this an error.

       Note also that WinSock ignores the first argument, so we don't worry
       about the fact that maxfd is computed incorrectly with WinSock (since
       curl_socket_t is unsigned in such cases and thus -1 is the largest
       value).
    */
    r = select((int)maxfd + 1,
#ifndef USE_WINSOCK
               &fds_read,
               &fds_write,
#else
               fds_read.fd_count ? &fds_read : NULL,
               fds_write.fd_count ? &fds_write : NULL,
#endif
               &fds_err, ptimeout);
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && error_not_EINTR)
      break;
    if(timeout_ms > 0) {
      pending_ms = timeout_ms - elapsed_ms;
      if(pending_ms <= 0) {
        r = 0;  /* Simulate a "call timed out" case */
        break;
      }
    }
  } while(r == -1);

  if(r < 0)
    return -1;
  if(r == 0)
    return 0;

  ret = 0;
  if(readfd0 != CURL_SOCKET_BAD) {
    if(FD_ISSET(readfd0, &fds_read))
      ret |= CURL_CSELECT_IN;
    if(FD_ISSET(readfd0, &fds_err))
      ret |= CURL_CSELECT_ERR;
  }
  if(readfd1 != CURL_SOCKET_BAD) {
    if(FD_ISSET(readfd1, &fds_read))
      ret |= CURL_CSELECT_IN2;
    if(FD_ISSET(readfd1, &fds_err))
      ret |= CURL_CSELECT_ERR;
  }
  if(writefd != CURL_SOCKET_BAD) {
    if(FD_ISSET(writefd, &fds_write))
      ret |= CURL_CSELECT_OUT;
    if(FD_ISSET(writefd, &fds_err))
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
  struct timeval initial_tv = {0, 0};
  bool fds_none = TRUE;
  unsigned int i;
  int pending_ms = 0;
  int error;
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
    r = Curl_wait_ms(timeout_ms);
    return r;
  }

  /* Avoid initial timestamp, avoid curlx_tvnow() call, when elapsed
     time in this function does not need to be measured. This happens
     when function is called with a zero timeout or a negative timeout
     value indicating a blocking call should be performed. */

  if(timeout_ms > 0) {
    pending_ms = timeout_ms;
    initial_tv = curlx_tvnow();
  }

#ifdef HAVE_POLL_FINE

  do {
    if(timeout_ms < 0)
      pending_ms = -1;
    else if(!timeout_ms)
      pending_ms = 0;
    r = poll(ufds, nfds, pending_ms);
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && error_not_EINTR)
      break;
    if(timeout_ms > 0) {
      pending_ms = timeout_ms - elapsed_ms;
      if(pending_ms <= 0) {
        r = 0;  /* Simulate a "call timed out" case */
        break;
      }
    }
  } while(r == -1);

  if(r < 0)
    return -1;
  if(r == 0)
    return 0;

  for(i = 0; i < nfds; i++) {
    if(ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    if(ufds[i].revents & POLLHUP)
      ufds[i].revents |= POLLIN;
    if(ufds[i].revents & POLLERR)
      ufds[i].revents |= (POLLIN|POLLOUT);
  }

#else  /* HAVE_POLL_FINE */

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

#ifdef USE_WINSOCK
  /* WinSock select() can't handle zero events.  See the comment about this in
     Curl_check_socket(). */
  if(fds_read.fd_count == 0 && fds_write.fd_count == 0
     && fds_err.fd_count == 0) {
    r = Curl_wait_ms(timeout_ms);
    return r;
  }
#endif

  ptimeout = (timeout_ms < 0) ? NULL : &pending_tv;

  do {
    if(timeout_ms > 0) {
      pending_tv.tv_sec = pending_ms / 1000;
      pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    }
    else if(!timeout_ms) {
      pending_tv.tv_sec = 0;
      pending_tv.tv_usec = 0;
    }
    r = select((int)maxfd + 1,
#ifndef USE_WINSOCK
               &fds_read, &fds_write, &fds_err,
#else
               /* WinSock select() can't handle fd_sets with zero bits set, so
                  don't give it such arguments.  See the comment about this in
                  Curl_check_socket().
               */
               fds_read.fd_count ? &fds_read : NULL,
               fds_write.fd_count ? &fds_write : NULL,
               fds_err.fd_count ? &fds_err : NULL,
#endif
               ptimeout);
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && error_not_EINTR)
      break;
    if(timeout_ms > 0) {
      pending_ms = timeout_ms - elapsed_ms;
      if(pending_ms <= 0) {
        r = 0;  /* Simulate a "call timed out" case */
        break;
      }
    }
  } while(r == -1);

  if(r < 0)
    return -1;
  if(r == 0)
    return 0;

  r = 0;
  for(i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if(ufds[i].fd == CURL_SOCKET_BAD)
      continue;
    if(FD_ISSET(ufds[i].fd, &fds_read))
      ufds[i].revents |= POLLIN;
    if(FD_ISSET(ufds[i].fd, &fds_write))
      ufds[i].revents |= POLLOUT;
    if(FD_ISSET(ufds[i].fd, &fds_err))
      ufds[i].revents |= POLLPRI;
    if(ufds[i].revents != 0)
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
   return rc;
}
#endif /* TPF */
