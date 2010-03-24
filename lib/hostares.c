/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <string.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif

#ifdef HAVE_PROCESS_H
#include <process.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"
#include "multiif.h"
#include "inet_pton.h"
#include "connect.h"
#include "select.h"
#include "progress.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for ares-enabled builds
 **********************************************************************/

#ifdef CURLRES_ARES

/*
 * Curl_resolv_fdset() is called when someone from the outside world (using
 * curl_multi_fdset()) wants to get our fd_set setup and we're talking with
 * ares. The caller must make sure that this function is only called when we
 * have a working ares channel.
 *
 * Returns: CURLE_OK always!
 */

int Curl_resolv_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks)

{
  struct timeval maxtime;
  struct timeval timebuf;
  struct timeval *timeout;
  int max = ares_getsock(conn->data->state.areschannel,
                         (ares_socket_t *)socks, numsocks);


  maxtime.tv_sec = CURL_TIMEOUT_RESOLVE;
  maxtime.tv_usec = 0;

  timeout = ares_timeout(conn->data->state.areschannel, &maxtime, &timebuf);

  Curl_expire(conn->data,
              (timeout->tv_sec * 1000) + (timeout->tv_usec/1000));

  return max;
}

/*
 * waitperform()
 *
 * 1) Ask ares what sockets it currently plays with, then
 * 2) wait for the timeout period to check for action on ares' sockets.
 * 3) tell ares to act on all the sockets marked as "with action"
 *
 * return number of sockets it worked on
 */

static int waitperform(struct connectdata *conn, int timeout_ms)
{
  struct SessionHandle *data = conn->data;
  int nfds;
  int bitmask;
  ares_socket_t socks[ARES_GETSOCK_MAXNUM];
  struct pollfd pfd[ARES_GETSOCK_MAXNUM];
  int i;
  int num = 0;

  bitmask = ares_getsock(data->state.areschannel, socks, ARES_GETSOCK_MAXNUM);

  for(i=0; i < ARES_GETSOCK_MAXNUM; i++) {
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
    if(pfd[i].events != 0)
      num++;
    else
      break;
  }

  if(num)
    nfds = Curl_poll(pfd, num, timeout_ms);
  else
    nfds = 0;

  if(!nfds)
    /* Call ares_process() unconditonally here, even if we simply timed out
       above, as otherwise the ares name resolve won't timeout! */
    ares_process_fd(data->state.areschannel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  else {
    /* move through the descriptors and ask for processing on them */
    for(i=0; i < num; i++)
      ares_process_fd(data->state.areschannel,
                      pfd[i].revents & (POLLRDNORM|POLLIN)?
                      pfd[i].fd:ARES_SOCKET_BAD,
                      pfd[i].revents & (POLLWRNORM|POLLOUT)?
                      pfd[i].fd:ARES_SOCKET_BAD);
  }
  return nfds;
}

/*
 * Curl_is_resolved() is called repeatedly to check if a previous name resolve
 * request has completed. It should also make sure to time-out if the
 * operation seems to take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns)
{
  struct SessionHandle *data = conn->data;

  *dns = NULL;

  waitperform(conn, 0);

  if(conn->async.done) {
    /* we're done, kill the ares handle */
    if(!conn->async.dns) {
      failf(data, "Could not resolve host: %s (%s)", conn->host.dispname,
            ares_strerror(conn->async.status));
      return CURLE_COULDNT_RESOLVE_HOST;
    }
    *dns = conn->async.dns;
  }

  return CURLE_OK;
}

/*
 * Curl_wait_for_resolv() waits for a resolve to finish. This function should
 * be avoided since using this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved, and
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred.
 */
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  CURLcode rc=CURLE_OK;
  struct SessionHandle *data = conn->data;
  long timeout;
  struct timeval now = Curl_tvnow();

  /* now, see if there's a connect timeout or a regular timeout to
     use instead of the default one */
  if(conn->data->set.connecttimeout)
    timeout = conn->data->set.connecttimeout;
  else if(conn->data->set.timeout)
    timeout = conn->data->set.timeout;
  else
    timeout = CURL_TIMEOUT_RESOLVE * 1000; /* default name resolve timeout */

  /* Wait for the name resolve query to complete. */
  while(1) {
    struct timeval *tvp, tv, store;
    long timediff;
    int itimeout;
    int timeout_ms;

    itimeout = (timeout > (long)INT_MAX) ? INT_MAX : (int)timeout;

    store.tv_sec = itimeout/1000;
    store.tv_usec = (itimeout%1000)*1000;

    tvp = ares_timeout(data->state.areschannel, &store, &tv);

    /* use the timeout period ares returned to us above if less than one
       second is left, otherwise just use 1000ms to make sure the progress
       callback gets called frequent enough */
    if(!tvp->tv_sec)
      timeout_ms = tvp->tv_usec/1000;
    else
      timeout_ms = 1000;

    waitperform(conn, timeout_ms);

    if(conn->async.done)
      break;

    if(Curl_pgrsUpdate(conn)) {
      rc = CURLE_ABORTED_BY_CALLBACK;
      timeout = -1; /* trigger the cancel below */
    }
    else {
      timediff = Curl_tvdiff(Curl_tvnow(), now); /* spent time */
      timeout -= timediff?timediff:1; /* always deduct at least 1 */
    }
    if(timeout < 0) {
      /* our timeout, so we cancel the ares operation */
      ares_cancel(data->state.areschannel);
      break;
    }
  }

  /* Operation complete, if the lookup was successful we now have the entry
     in the cache. */

  if(entry)
    *entry = conn->async.dns;

  if(!conn->async.dns) {
    /* a name was not resolved */
    if((timeout < 0) || (conn->async.status == ARES_ETIMEOUT)) {
      if (conn->bits.httpproxy) {
        failf(data, "Resolving proxy timed out: %s", conn->proxy.dispname);
        rc = CURLE_COULDNT_RESOLVE_PROXY;
      }
      else {
        failf(data, "Resolving host timed out: %s", conn->host.dispname);
        rc = CURLE_COULDNT_RESOLVE_HOST;
      }
    }
    else if(conn->async.done) {
      if (conn->bits.httpproxy) {
        failf(data, "Could not resolve proxy: %s (%s)", conn->proxy.dispname,
              ares_strerror(conn->async.status));
        rc = CURLE_COULDNT_RESOLVE_PROXY;
      }
      else {
        failf(data, "Could not resolve host: %s (%s)", conn->host.dispname,
              ares_strerror(conn->async.status));
        rc = CURLE_COULDNT_RESOLVE_HOST;
      }
    }
    else
      rc = CURLE_OPERATION_TIMEDOUT;

    /* close the connection, since we can't return failure here without
       cleaning up this connection properly */
    conn->bits.close = TRUE;
  }

  return rc;
}

/*
 * ares_query_completed_cb() is the callback that ares will call when
 * the host query initiated by ares_gethostbyname() from Curl_getaddrinfo(),
 * when using ares, is completed either successfully or with failure.
 */
static void ares_query_completed_cb(void *arg,  /* (struct connectdata *) */
                                    int status,
#ifdef HAVE_CARES_CALLBACK_TIMEOUTS
                                    int timeouts,
#endif
                                    struct hostent *hostent)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct Curl_addrinfo * ai = NULL;

#ifdef HAVE_CARES_CALLBACK_TIMEOUTS
  (void)timeouts; /* ignored */
#endif

  if (status == CURL_ASYNC_SUCCESS) {
    ai = Curl_he2ai(hostent, conn->async.port);
  }

  (void)Curl_addrinfo_callback(arg, status, ai);
}

/*
 * Curl_getaddrinfo() - when using ares
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the forth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
                                int port,
                                int *waitp)
{
  char *bufp;
  struct SessionHandle *data = conn->data;
  struct in_addr in;
  int family = PF_INET;
#ifdef ENABLE_IPV6 /* CURLRES_IPV6 */
  struct in6_addr in6;
#endif /* CURLRES_IPV6 */

  *waitp = 0; /* default to synchronous response */

  /* First check if this is an IPv4 address string */
  if(Curl_inet_pton(AF_INET, hostname, &in) > 0) {
    /* This is a dotted IP address 123.123.123.123-style */
    return Curl_ip2addr(AF_INET, &in, hostname, port);
  }

#ifdef ENABLE_IPV6 /* CURLRES_IPV6 */
  /* Otherwise, check if this is an IPv6 address string */
  if (Curl_inet_pton (AF_INET6, hostname, &in6) > 0) {
    /* This must be an IPv6 address literal.  */
    return Curl_ip2addr(AF_INET6, &in6, hostname, port);
  }

  switch(data->set.ip_version) {
  default:
#if ARES_VERSION >= 0x010601
    family = PF_UNSPEC; /* supported by c-ares since 1.6.1, so for older
                           c-ares versions this just falls through and defaults
                           to PF_INET */
    break;
#endif
  case CURL_IPRESOLVE_V4:
    family = PF_INET;
    break;
  case CURL_IPRESOLVE_V6:
    family = PF_INET6;
    break;
  }
#endif /* CURLRES_IPV6 */

  bufp = strdup(hostname);

  if(bufp) {
    Curl_safefree(conn->async.hostname);
    conn->async.hostname = bufp;
    conn->async.port = port;
    conn->async.done = FALSE; /* not done */
    conn->async.status = 0;   /* clear */
    conn->async.dns = NULL;   /* clear */

    /* areschannel is already setup in the Curl_open() function */
    ares_gethostbyname(data->state.areschannel, hostname, family,
                       (ares_host_callback)ares_query_completed_cb, conn);

    *waitp = 1; /* expect asynchronous response */
  }
  return NULL; /* no struct yet */
}
#endif /* CURLRES_ARES */
