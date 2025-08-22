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

#include <curl/curl.h>

#include "urldata.h"
#include "connect.h"
#include "select.h"
#include "curl_trc.h"
#include "curlx/timediff.h"
#include "curlx/wait.h"
#include "curlx/warnless.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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
    return curlx_wait_ms(timeout_ms);
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
    return curlx_wait_ms(timeout_ms);
  }

  /* Avoid initial timestamp, avoid curlx_now() call, when elapsed
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
    return curlx_wait_ms(timeout_ms);
  }

  /* Avoid initial timestamp, avoid curlx_now() call, when elapsed
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
    if((r == -1) && (SOCKERRNO == SOCKEINTR))
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
    if((r == -1) && (SOCKERRNO == SOCKEINTR))
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

void Curl_pollfds_reset(struct curl_pollfds *cpfds)
{
  cpfds->n = 0;
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
  for(i = 0; i < ps->n; i++) {
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

void Curl_waitfds_init(struct Curl_waitfds *cwfds,
                       struct curl_waitfd *static_wfds,
                       unsigned int static_count)
{
  DEBUGASSERT(cwfds);
  DEBUGASSERT(static_wfds || !static_count);
  memset(cwfds, 0, sizeof(*cwfds));
  cwfds->wfds = static_wfds;
  cwfds->count = static_count;
}

static unsigned int cwfds_add_sock(struct Curl_waitfds *cwfds,
                                   curl_socket_t sock, short events)
{
  int i;
  if(!cwfds->wfds) {
    DEBUGASSERT(!cwfds->count && !cwfds->n);
    return 1;
  }
  if(cwfds->n <= INT_MAX) {
    for(i = (int)cwfds->n - 1; i >= 0; --i) {
      if(sock == cwfds->wfds[i].fd) {
        cwfds->wfds[i].events |= events;
        return 0;
      }
    }
  }
  /* not folded, add new entry */
  if(cwfds->n < cwfds->count) {
    cwfds->wfds[cwfds->n].fd = sock;
    cwfds->wfds[cwfds->n].events = events;
    ++cwfds->n;
  }
  return 1;
}

unsigned int Curl_waitfds_add_ps(struct Curl_waitfds *cwfds,
                                 struct easy_pollset *ps)
{
  size_t i;
  unsigned int need = 0;

  DEBUGASSERT(cwfds);
  DEBUGASSERT(ps);
  for(i = 0; i < ps->n; i++) {
    short events = 0;
    if(ps->actions[i] & CURL_POLL_IN)
      events |= CURL_WAIT_POLLIN;
    if(ps->actions[i] & CURL_POLL_OUT)
      events |= CURL_WAIT_POLLOUT;
    if(events)
      need += cwfds_add_sock(cwfds, ps->sockets[i], events);
  }
  return need;
}

void Curl_pollset_reset(struct easy_pollset *ps)
{
  unsigned int i;
  ps->n = 0;
#ifdef DEBUGBUILD
  DEBUGASSERT(ps->init == CURL_EASY_POLLSET_MAGIC);
#endif
  DEBUGASSERT(ps->count);
  for(i = 0; i < ps->count; i++)
    ps->sockets[i] = CURL_SOCKET_BAD;
  memset(ps->actions, 0, ps->count * sizeof(ps->actions[0]));
}

void Curl_pollset_init(struct easy_pollset *ps)
{
#ifdef DEBUGBUILD
  ps->init = CURL_EASY_POLLSET_MAGIC;
#endif
  ps->sockets = ps->def_sockets;
  ps->actions = ps->def_actions;
  ps->count = CURL_ARRAYSIZE(ps->def_sockets);
  ps->n = 0;
  Curl_pollset_reset(ps);
}

struct easy_pollset *Curl_pollset_create(void)
{
  struct easy_pollset *ps = calloc(1, sizeof(*ps));
  if(ps)
    Curl_pollset_init(ps);
  return ps;
}

void Curl_pollset_cleanup(struct easy_pollset *ps)
{
#ifdef DEBUGBUILD
  DEBUGASSERT(ps->init == CURL_EASY_POLLSET_MAGIC);
#endif
  if(ps->sockets != ps->def_sockets) {
    free(ps->sockets);
    ps->sockets = ps->def_sockets;
  }
  if(ps->actions != ps->def_actions) {
    free(ps->actions);
    ps->actions = ps->def_actions;
  }
  ps->count = CURL_ARRAYSIZE(ps->def_sockets);
  Curl_pollset_reset(ps);
}

void Curl_pollset_move(struct easy_pollset *to, struct easy_pollset *from)
{
  Curl_pollset_cleanup(to); /* deallocate anything in to */
  if(from->sockets != from->def_sockets) {
    DEBUGASSERT(from->actions != from->def_actions);
    to->sockets = from->sockets;
    to->actions = from->actions;
    to->count = from->count;
    to->n = from->n;
    Curl_pollset_init(from);
  }
  else {
    DEBUGASSERT(to->sockets == to->def_sockets);
    DEBUGASSERT(to->actions == to->def_actions);
    memcpy(to->sockets, from->sockets, to->count * sizeof(to->sockets[0]));
    memcpy(to->actions, from->actions, to->count * sizeof(to->actions[0]));
    to->n = from->n;
    Curl_pollset_init(from);
  }
}

/**
 *
 */
CURLcode Curl_pollset_change(struct Curl_easy *data,
                             struct easy_pollset *ps, curl_socket_t sock,
                             int add_flags, int remove_flags)
{
  unsigned int i;

#ifdef DEBUGBUILD
  DEBUGASSERT(ps->init == CURL_EASY_POLLSET_MAGIC);
#endif

  (void)data;
  DEBUGASSERT(VALID_SOCK(sock));
  if(!VALID_SOCK(sock))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  DEBUGASSERT(add_flags <= (CURL_POLL_IN|CURL_POLL_OUT));
  DEBUGASSERT(remove_flags <= (CURL_POLL_IN|CURL_POLL_OUT));
  DEBUGASSERT((add_flags&remove_flags) == 0); /* no overlap */
  for(i = 0; i < ps->n; ++i) {
    if(ps->sockets[i] == sock) {
      ps->actions[i] &= (unsigned char)(~remove_flags);
      ps->actions[i] |= (unsigned char)add_flags;
      /* all gone? remove socket */
      if(!ps->actions[i]) {
        if((i + 1) < ps->n) {
          memmove(&ps->sockets[i], &ps->sockets[i + 1],
                  (ps->n - (i + 1)) * sizeof(ps->sockets[0]));
          memmove(&ps->actions[i], &ps->actions[i + 1],
                  (ps->n - (i + 1)) * sizeof(ps->actions[0]));
        }
        --ps->n;
      }
      return CURLE_OK;
    }
  }
  /* not present */
  if(add_flags) {
    if(i >= ps->count) { /* need to grow */
      unsigned int new_count = CURLMAX(ps->count * 2, 8);
      curl_socket_t *nsockets;
      unsigned char *nactions;

      CURL_TRC_M(data, "growing pollset capacity from %u to %u",
                 ps->count, new_count);
      if(new_count <= ps->count)
        return CURLE_OUT_OF_MEMORY;
      nsockets = calloc(new_count, sizeof(nsockets[0]));
      if(!nsockets)
        return CURLE_OUT_OF_MEMORY;
      nactions = calloc(new_count, sizeof(nactions[0]));
      if(!nactions) {
        free(nsockets);
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(nsockets, ps->sockets, ps->count * sizeof(ps->sockets[0]));
      memcpy(nactions, ps->actions, ps->count * sizeof(ps->actions[0]));
      if(ps->sockets != ps->def_sockets)
        free(ps->sockets);
      ps->sockets = nsockets;
      if(ps->actions != ps->def_actions)
        free(ps->actions);
      ps->actions = nactions;
      ps->count = new_count;
    }
    DEBUGASSERT(i < ps->count);
    if(i < ps->count) {
      ps->sockets[i] = sock;
      ps->actions[i] = (unsigned char)add_flags;
      ps->n = i + 1;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_pollset_set(struct Curl_easy *data,
                          struct easy_pollset *ps, curl_socket_t sock,
                          bool do_in, bool do_out)
{
  return Curl_pollset_change(data, ps, sock,
                             (do_in ? CURL_POLL_IN : 0)|
                             (do_out ? CURL_POLL_OUT : 0),
                             (!do_in ? CURL_POLL_IN : 0)|
                             (!do_out ? CURL_POLL_OUT : 0));
}

int Curl_pollset_poll(struct Curl_easy *data,
                      struct easy_pollset *ps,
                      timediff_t timeout_ms)
{
  struct pollfd *pfds;
  unsigned int i, npfds;
  int result;

  (void)data;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  if(!ps->n)
    return curlx_wait_ms(timeout_ms);

  pfds = calloc(ps->n, sizeof(*pfds));
  if(!pfds)
    return -1;

  npfds = 0;
  for(i = 0; i < ps->n; ++i) {
    short events = 0;
    if(ps->actions[i] & CURL_POLL_IN) {
      events |= POLLIN;
    }
    if(ps->actions[i] & CURL_POLL_OUT) {
      events |= POLLOUT;
    }
    if(events) {
      pfds[npfds].fd = ps->sockets[i];
      pfds[npfds].events = events;
      ++npfds;
    }
  }

  result = Curl_poll(pfds, npfds, timeout_ms);
  free(pfds);
  return result;
}

void Curl_pollset_check(struct Curl_easy *data,
                        struct easy_pollset *ps, curl_socket_t sock,
                        bool *pwant_read, bool *pwant_write)
{
  unsigned int i;

  (void)data;
  DEBUGASSERT(VALID_SOCK(sock));
  for(i = 0; i < ps->n; ++i) {
    if(ps->sockets[i] == sock) {
      *pwant_read = !!(ps->actions[i] & CURL_POLL_IN);
      *pwant_write = !!(ps->actions[i] & CURL_POLL_OUT);
      return;
    }
  }
  *pwant_read = *pwant_write = FALSE;
}

bool Curl_pollset_want_read(struct Curl_easy *data,
                            struct easy_pollset *ps,
                            curl_socket_t sock)
{
  unsigned int i;
  (void)data;
  for(i = 0; i < ps->n; ++i) {
    if((ps->sockets[i] == sock) && (ps->actions[i] & CURL_POLL_IN))
      return TRUE;
  }
  return FALSE;
}
