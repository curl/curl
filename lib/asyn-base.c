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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef USE_ARES
#include <ares.h>
#include <ares_version.h> /* really old c-ares did not include this by
                             itself */
#endif

#include "urldata.h"
#include "asyn.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "multiif.h"
#include "select.h"
#include "share.h"
#include "url.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for builds using asynchronous name resolves
 **********************************************************************/
#ifdef CURLRES_ASYNCH


#ifdef USE_ARES

#if ARES_VERSION < 0x010600
#error "requires c-ares 1.6.0 or newer"
#endif

/*
 * Curl_ares_pollset() is called when the outside world (using
 * curl_multi_fdset()) wants to get our fd_set setup and we are talking with
 * ares. The caller must make sure that this function is only called when we
 * have a working ares channel.
 *
 * Returns: sockets-in-use-bitmap
 */


CURLcode Curl_ares_pollset(struct Curl_easy *data,
                           ares_channel channel,
                           struct easy_pollset *ps)
{
  struct timeval maxtime = { CURL_TIMEOUT_RESOLVE, 0 };
  struct timeval timebuf;
  curl_socket_t sockets[16];  /* ARES documented limit */
  unsigned int bitmap, i;
  struct timeval *timeout;
  timediff_t milli;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(channel);
  if(!channel)
    return CURLE_FAILED_INIT;

  bitmap = ares_getsock(channel, (ares_socket_t *)sockets,
                        CURL_ARRAYSIZE(sockets));
  for(i = 0; i < CURL_ARRAYSIZE(sockets); ++i) {
    int flags = 0;
    if(ARES_GETSOCK_READABLE(bitmap, i))
      flags |= CURL_POLL_IN;
    if(ARES_GETSOCK_WRITABLE(bitmap, i))
      flags |= CURL_POLL_OUT;
    if(!flags)
      break;
    result = Curl_pollset_change(data, ps, sockets[i], flags, 0);
    if(result)
      return result;
  }

  timeout = ares_timeout(channel, &maxtime, &timebuf);
  if(!timeout)
    timeout = &maxtime;
  milli = curlx_tvtoms(timeout);
  Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
  return result;
}

/*
 * Curl_ares_perform()
 *
 * 1) Ask ares what sockets it currently plays with, then
 * 2) wait for the timeout period to check for action on ares' sockets.
 * 3) tell ares to act on all the sockets marked as "with action"
 *
 * return number of sockets it worked on, or -1 on error
 */
int Curl_ares_perform(ares_channel channel,
                      timediff_t timeout_ms)
{
  int nfds;
  int bitmask;
  ares_socket_t socks[ARES_GETSOCK_MAXNUM];
  struct pollfd pfd[ARES_GETSOCK_MAXNUM];
  int i;
  int num = 0;

  if(!channel)
    return 0;

  bitmask = ares_getsock(channel, socks, ARES_GETSOCK_MAXNUM);

  for(i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
    pfd[i].events = 0;
    pfd[i].revents = 0;
    if(ARES_GETSOCK_READABLE(bitmask, i)) {
      pfd[i].fd = socks[i];
      pfd[i].events |= POLLRDNORM|POLLIN;
    }
    if(ARES_GETSOCK_WRITABLE(bitmask, i)) {
      pfd[i].fd = socks[i];
      pfd[i].events |= POLLWRNORM|POLLOUT;
    }
    if(pfd[i].events)
      num++;
    else
      break;
  }

  if(num) {
    nfds = Curl_poll(pfd, (unsigned int)num, timeout_ms);
    if(nfds < 0)
      return -1;
  }
  else
    nfds = 0;

  if(!nfds)
    /* Call ares_process() unconditionally here, even if we simply timed out
       above, as otherwise the ares name resolve will not timeout! */
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  else {
    /* move through the descriptors and ask for processing on them */
    for(i = 0; i < num; i++)
      ares_process_fd(channel,
                      (pfd[i].revents & (POLLRDNORM|POLLIN)) ?
                      pfd[i].fd : ARES_SOCKET_BAD,
                      (pfd[i].revents & (POLLWRNORM|POLLOUT)) ?
                      pfd[i].fd : ARES_SOCKET_BAD);
  }
  return nfds;
}

#endif

#endif /* CURLRES_ASYNCH */

#ifdef USE_CURL_ASYNC

#include "doh.h"

void Curl_async_shutdown(struct Curl_easy *data)
{
#ifdef CURLRES_ARES
  Curl_async_ares_shutdown(data);
#endif
#ifdef CURLRES_THREADED
  Curl_async_thrdd_shutdown(data);
#endif
#ifndef CURL_DISABLE_DOH
  Curl_doh_cleanup(data);
#endif
  Curl_safefree(data->state.async.hostname);
}

void Curl_async_destroy(struct Curl_easy *data)
{
#ifdef CURLRES_ARES
  Curl_async_ares_destroy(data);
#endif
#ifdef CURLRES_THREADED
  Curl_async_thrdd_destroy(data);
#endif
#ifndef CURL_DISABLE_DOH
  Curl_doh_cleanup(data);
#endif
  Curl_safefree(data->state.async.hostname);
}

#endif /* USE_CURL_ASYNC */
