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

#include <signal.h>

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

/* Winsock and TPF sockets are not in range [0..FD_SETSIZE-1] */

/*  There are various ways to wait for a socket to be ready to give or take
 *  data.  None of them are perfect.  
 *
 *  select() is available everywhere, but cannot take a file
 *  descriptor numerically greater than FD_SETSIZE but cannot be reliably
 *  interrupted by a signal.
 *
 *  pselect() works with signals, but still has the file descriptor problem.
 *  And some older systems don't have it.
 *
 *  poll() (and equivalently on Windows, WSAPoll()) can take any file
 *  descriptor, but has the signal problem.  And some older systems
 *  don't have it.
 *
 *  The signal issue is this:  We would like to be able to avoid the
 *  wait if a signal has arrived since we last checked for it.  All
 *  these methods terminate the wait (with EINTR) if a signal arrives
 *  while the waiting is underway, so it's just signals that happen
 *  shortly before the wait that are a problem.  With pselect(), this
 *  is possible because it has the ability to simultaneously unblock
 *  signals _after_ the wait begins.  So you just block signals, then
 *  check for arrival, then assuming no signals have arrived, call
 *  pselect() with an argument that says to unblock signals.  Any
 *  signal that arrived after you blocked will thus interrupt the wait
 *  and pselect() returns immediately.
 * 
 *  Curl_pselect() is our compromise among these.  We use poll()
 *  whenever it is available and select() otherwise.  We emulate
 *  pselect-like signal behavior by unblocking signals just before
 *  calling poll() or select() and re-blocking after.  This only
 *  _approximates_ pselect(), because there is a window in which a
 *  signal may arrive and we wait anyway.
 *
 *  To reduce that window, we use pselect(), if it is available --
 *  with no file descriptors -- just before the poll() or select() in
 *  order to detect signals that arrived between when the caller
 *  blocked signals and when he called Curl_pselect().
 *
 *  Curl_select() is for callers who want us to ignore caught signals and
 *  wait until a socket is ready or the timeout expires.  We implement that
 *  simply as a loop around Curl_pselect().
 *
 *  There is a way to add signal interruptibility to poll(), which we
 *  don't provide today: Let caller give us a file descriptor to add
 *  to our list of wait-for-readable file descriptors.  Caller passes
 *  us the fd of a pipe.  He doesn't block signals and his signal
 *  handler writes to the other end of that pipe.  Therefore, a signal
 *  causes poll() to return, even if received before poll() was
 *  called.
 */

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

/*
 * This function unblocks a set of signal classes momentarily, to allow any
 * the process to receive any presently blocked signal.  If there exists
 * a handler for that, it will run now.  If not, it will typically
 * terminate the process.
 *
 * We return 1 if as a result of the unblocking, a signal was
 * received, caught and handled.  0 otherwise.
 *
 * On a system that does not have pselect(), we always return 0, even if
 * signals were received.
 */
int receive_signals(sigset_t * sigmask)
{
#ifdef HAVE_PSELECT
  struct timespec zeroTime = {0, 0};

  /* Note that on older Linux, pselect() is imperfect -- the kernel doesn't
     have a pselect() system call, so the GNU C Library implements it
     with sigprocmask() followed by select(), which means the result is
     the same as with the code below for systmes with no pselect() at all.
  */
  if (pselect(0, NULL, NULL, NULL, &zeroTime, sigmask) == 0)
      return 0;
  else
      return 1;
#else
  sigset_t oldmask;

  sigprocmask(SIG_SETMASK, sigmask, &oldmask);
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  return 0;
#endif
}

#if defined(HAVE_POLL_FINE) || defined(CURL_HAVE_WSAPOLL)
  #define USE_POLL_FOR_SELECT 1
#else
  #if defined(HAVE_SELECT)
    #define USE_POLL_FOR_SELECT 0
  #else
    #error "You don't appear to have either poll() or select()."
  #endif
#endif

#if USE_POLL_FOR_SELECT

static int select_with_poll(curl_socket_t readfd, curl_socket_t writefd,
                            int timeout_ms)
{
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

#ifdef CURL_HAVE_WSAPOLL
  r = WSAPoll(pfd, num, timeout_ms);
#else
  r = poll(pfd, num, timeout_ms);
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
}

#endif USE_POLL_FOR_SELECT

static int select_with_select(curl_socket_t readfd, curl_socket_t writefd,
                              int timeout_ms)
{
  struct timeval timeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t maxfd;
  int r;
  int ret;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  if((readfd == CURL_SOCKET_BAD) && (writefd == CURL_SOCKET_BAD)) {
    /* According to POSIX we should pass in NULL pointers if we don't want to
       wait for anything in particular but just use the timeout function.
       Windows however returns immediately if done so. I copied the MSDOS
       delay() use from src/main.c that already had this work-around. */
#ifdef WIN32
    Sleep(timeout_ms);
#elif defined(__MSDOS__)
    delay(timeout_ms);
#else
    select(0, NULL, NULL, NULL, &timeout);
#endif
    return 0;
  }

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

  r = select((int)maxfd + 1, &fds_read, &fds_write, &fds_err, &timeout);

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
}

/*
 * This is an internal function used for waiting for read or write
 * events on single file descriptors.  It attempts to replace select()
 * in order to avoid limits with FD_SETSIZE.
 *
 * Return values:
 *   -1 = system call error, including interrupted by signal
 *    0 = timeout
 *    CSELECT_IN | CSELECT_OUT | CSELECT_ERR
 */
int Curl_pselect(curl_socket_t readfd, curl_socket_t writefd, int timeout_ms,
                 sigset_t * sigmask)
{
  int ret;
  sigset_t oldmask;

  if (sigmask && receive_signals(sigmask)) {
      SET_SOCKERRNO(EINTR);
      ret = -1;
  } else {
    if (sigmask)
      sigprocmask(SIG_SETMASK, sigmask, &oldmask);
#if USE_POLL_FOR_SELECT
    ret = select_with_poll(readfd, writefd, timeout_ms);
#else
    ret = select_with_select(readfd, writefd, timeout_ms);
#endif
    if (sigmask)
      sigprocmask(SIG_SETMASK, &oldmask, NULL);
  }
  return ret;
}

int Curl_select(curl_socket_t readfd, curl_socket_t writefd, int timeout_ms)
{
  int r;
  do {
    r = Curl_pselect(readfd, writefd, timeout_ms, NULL);
  } while((r == -1) && (SOCKERRNO == EINTR));

  return r;
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
#ifdef CURL_HAVE_WSAPOLL
    r = WSAPoll(ufds, nfds, timeout_ms);
#else
    r = poll(ufds, nfds, timeout_ms);
#endif
  } while((r == -1) && (SOCKERRNO == EINTR));
#else  /* HAVE_POLL_FINE */
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
#if !defined(USE_WINSOCK) && !defined(TPF)
    /* Winsock and TPF sockets are not in range [0..FD_SETSIZE-1] */
    if (ufds[i].fd >= FD_SETSIZE) {
      SET_SOCKERRNO(EINVAL);
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
  } while((r == -1) && (SOCKERRNO == EINTR));

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
