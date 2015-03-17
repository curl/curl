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

#ifdef HAVE_LIMITS_H
#include <limits.h>
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
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef HAVE_PROCESS_H
#include <process.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

/***********************************************************************
 * Only for ares-enabled builds
 * And only for functions that fulfill the asynch resolver backend API
 * as defined in asyn.h, nothing else belongs in this file!
 **********************************************************************/

#ifdef CURLRES_ARES

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
#include "curl_printf.h"

#  if defined(CURL_STATICLIB) && !defined(CARES_STATICLIB) && \
     (defined(WIN32) || defined(_WIN32) || defined(__SYMBIAN32__))
#    define CARES_STATICLIB
#  endif
#  include <ares.h>
#  include <ares_version.h> /* really old c-ares didn't include this by
                               itself */

#if ARES_VERSION >= 0x010500
/* c-ares 1.5.0 or later, the callback proto is modified */
#define HAVE_CARES_CALLBACK_TIMEOUTS 1
#endif

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

struct ResolverResults {
  int num_pending; /* number of ares_gethostbyname() requests */
  Curl_addrinfo *temp_ai; /* intermediary result while fetching c-ares parts */
  int last_status;
};

/*
 * Curl_resolver_global_init() - the generic low-level asynchronous name
 * resolve API.  Called from curl_global_init() to initialize global resolver
 * environment.  Initializes ares library.
 */
int Curl_resolver_global_init(void)
{
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
  if(ares_library_init(ARES_LIB_INIT_ALL)) {
    return CURLE_FAILED_INIT;
  }
#endif
  return CURLE_OK;
}

/*
 * Curl_resolver_global_cleanup()
 *
 * Called from curl_global_cleanup() to destroy global resolver environment.
 * Deinitializes ares library.
 */
void Curl_resolver_global_cleanup(void)
{
#ifdef CARES_HAVE_ARES_LIBRARY_CLEANUP
  ares_library_cleanup();
#endif
}

/*
 * Curl_resolver_init()
 *
 * Called from curl_easy_init() -> Curl_open() to initialize resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).  Fills the passed pointer by the initialized ares_channel.
 */
CURLcode Curl_resolver_init(void **resolver)
{
  int status = ares_init((ares_channel*)resolver);
  if(status != ARES_SUCCESS) {
    if(status == ARES_ENOMEM)
      return CURLE_OUT_OF_MEMORY;
    else
      return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
  /* make sure that all other returns from this function should destroy the
     ares channel before returning error! */
}

/*
 * Curl_resolver_cleanup()
 *
 * Called from curl_easy_cleanup() -> Curl_close() to cleanup resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).  Destroys the ares channel.
 */
void Curl_resolver_cleanup(void *resolver)
{
  ares_destroy((ares_channel)resolver);
}

/*
 * Curl_resolver_duphandle()
 *
 * Called from curl_easy_duphandle() to duplicate resolver URL-state specific
 * environment ('resolver' member of the UrlState structure).  Duplicates the
 * 'from' ares channel and passes the resulting channel to the 'to' pointer.
 */
int Curl_resolver_duphandle(void **to, void *from)
{
  /* Clone the ares channel for the new handle */
  if(ARES_SUCCESS != ares_dup((ares_channel*)to, (ares_channel)from))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static void destroy_async_data (struct Curl_async *async);

/*
 * Cancel all possibly still on-going resolves for this connection.
 */
void Curl_resolver_cancel(struct connectdata *conn)
{
  if(conn->data && conn->data->state.resolver)
    ares_cancel((ares_channel)conn->data->state.resolver);
  destroy_async_data(&conn->async);
}

/*
 * destroy_async_data() cleans up async resolver data.
 */
static void destroy_async_data (struct Curl_async *async)
{
  free(async->hostname);

  if(async->os_specific) {
    struct ResolverResults *res = (struct ResolverResults *)async->os_specific;
    if(res) {
      if(res->temp_ai) {
        Curl_freeaddrinfo(res->temp_ai);
        res->temp_ai = NULL;
      }
      free(res);
    }
    async->os_specific = NULL;
  }

  async->hostname = NULL;
}

/*
 * Curl_resolver_getsock() is called when someone from the outside world
 * (using curl_multi_fdset()) wants to get our fd_set setup and we're talking
 * with ares. The caller must make sure that this function is only called when
 * we have a working ares channel.
 *
 * Returns: sockets-in-use-bitmap
 */

int Curl_resolver_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks)

{
  struct timeval maxtime;
  struct timeval timebuf;
  struct timeval *timeout;
  long milli;
  int max = ares_getsock((ares_channel)conn->data->state.resolver,
                         (ares_socket_t *)socks, numsocks);

  maxtime.tv_sec = CURL_TIMEOUT_RESOLVE;
  maxtime.tv_usec = 0;

  timeout = ares_timeout((ares_channel)conn->data->state.resolver, &maxtime,
                         &timebuf);
  milli = (timeout->tv_sec * 1000) + (timeout->tv_usec/1000);
  if(milli == 0)
    milli += 10;
  Curl_expire_latest(conn->data, milli);

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

  bitmask = ares_getsock((ares_channel)data->state.resolver, socks,
                         ARES_GETSOCK_MAXNUM);

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
    ares_process_fd((ares_channel)data->state.resolver, ARES_SOCKET_BAD,
                    ARES_SOCKET_BAD);
  else {
    /* move through the descriptors and ask for processing on them */
    for(i=0; i < num; i++)
      ares_process_fd((ares_channel)data->state.resolver,
                      pfd[i].revents & (POLLRDNORM|POLLIN)?
                      pfd[i].fd:ARES_SOCKET_BAD,
                      pfd[i].revents & (POLLWRNORM|POLLOUT)?
                      pfd[i].fd:ARES_SOCKET_BAD);
  }
  return nfds;
}

/*
 * Curl_resolver_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_resolver_is_resolved(struct connectdata *conn,
                                   struct Curl_dns_entry **dns)
{
  struct SessionHandle *data = conn->data;
  struct ResolverResults *res = (struct ResolverResults *)
    conn->async.os_specific;
  CURLcode result = CURLE_OK;

  *dns = NULL;

  waitperform(conn, 0);

  if(res && !res->num_pending) {
    (void)Curl_addrinfo_callback(conn, res->last_status, res->temp_ai);
    /* temp_ai ownership is moved to the connection, so we need not free-up
       them */
    res->temp_ai = NULL;
    if(!conn->async.dns) {
      failf(data, "Could not resolve: %s (%s)",
            conn->async.hostname, ares_strerror(conn->async.status));
      result = conn->bits.proxy?CURLE_COULDNT_RESOLVE_PROXY:
        CURLE_COULDNT_RESOLVE_HOST;
    }
    else
      *dns = conn->async.dns;

    destroy_async_data(&conn->async);
  }

  return result;
}

/*
 * Curl_resolver_wait_resolv()
 *
 * waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved, and
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred.
 */
CURLcode Curl_resolver_wait_resolv(struct connectdata *conn,
                                   struct Curl_dns_entry **entry)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  long timeout;
  struct timeval now = Curl_tvnow();
  struct Curl_dns_entry *temp_entry;

  timeout = Curl_timeleft(data, &now, TRUE);
  if(!timeout)
    timeout = CURL_TIMEOUT_RESOLVE * 1000; /* default name resolve timeout */

  /* Wait for the name resolve query to complete. */
  for(;;) {
    struct timeval *tvp, tv, store;
    long timediff;
    int itimeout;
    int timeout_ms;

    itimeout = (timeout > (long)INT_MAX) ? INT_MAX : (int)timeout;

    store.tv_sec = itimeout/1000;
    store.tv_usec = (itimeout%1000)*1000;

    tvp = ares_timeout((ares_channel)data->state.resolver, &store, &tv);

    /* use the timeout period ares returned to us above if less than one
       second is left, otherwise just use 1000ms to make sure the progress
       callback gets called frequent enough */
    if(!tvp->tv_sec)
      timeout_ms = (int)(tvp->tv_usec/1000);
    else
      timeout_ms = 1000;

    waitperform(conn, timeout_ms);
    Curl_resolver_is_resolved(conn, &temp_entry);

    if(conn->async.done)
      break;

    if(Curl_pgrsUpdate(conn)) {
      result = CURLE_ABORTED_BY_CALLBACK;
      timeout = -1; /* trigger the cancel below */
    }
    else {
      struct timeval now2 = Curl_tvnow();
      timediff = Curl_tvdiff(now2, now); /* spent time */
      timeout -= timediff?timediff:1; /* always deduct at least 1 */
      now = now2; /* for next loop */
    }

    if(timeout < 0) {
      /* our timeout, so we cancel the ares operation */
      ares_cancel((ares_channel)data->state.resolver);
      break;
    }
  }

  /* Operation complete, if the lookup was successful we now have the entry
     in the cache. */
  if(entry)
    *entry = conn->async.dns;

  if(result)
    /* close the connection, since we can't return failure here without
       cleaning up this connection properly.
       TODO: remove this action from here, it is not a name resolver decision.
    */
    connclose(conn, "c-ares resolve failed");

  return result;
}

/* Connects results to the list */
static void compound_results(struct ResolverResults *res,
                             Curl_addrinfo *ai)
{
  Curl_addrinfo *ai_tail;
  if(!ai)
    return;
  ai_tail = ai;

  while(ai_tail->ai_next)
    ai_tail = ai_tail->ai_next;

  /* Add the new results to the list of old results. */
  ai_tail->ai_next = res->temp_ai;
  res->temp_ai = ai;
}

/*
 * ares_query_completed_cb() is the callback that ares will call when
 * the host query initiated by ares_gethostbyname() from Curl_getaddrinfo(),
 * when using ares, is completed either successfully or with failure.
 */
static void query_completed_cb(void *arg,  /* (struct connectdata *) */
                               int status,
#ifdef HAVE_CARES_CALLBACK_TIMEOUTS
                               int timeouts,
#endif
                               struct hostent *hostent)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct ResolverResults *res;

#ifdef HAVE_CARES_CALLBACK_TIMEOUTS
  (void)timeouts; /* ignored */
#endif

  if(ARES_EDESTRUCTION == status)
    /* when this ares handle is getting destroyed, the 'arg' pointer may not
       be valid so only defer it when we know the 'status' says its fine! */
    return;

  res = (struct ResolverResults *)conn->async.os_specific;
  res->num_pending--;

  if(CURL_ASYNC_SUCCESS == status) {
    Curl_addrinfo *ai = Curl_he2ai(hostent, conn->async.port);
    if(ai) {
      compound_results(res, ai);
    }
  }
  /* A successful result overwrites any previous error */
  if(res->last_status != ARES_SUCCESS)
    res->last_status = status;
}

/*
 * Curl_resolver_getaddrinfo() - when using ares
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the forth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
Curl_addrinfo *Curl_resolver_getaddrinfo(struct connectdata *conn,
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
  if(Curl_inet_pton (AF_INET6, hostname, &in6) > 0)
    /* This must be an IPv6 address literal.  */
    return Curl_ip2addr(AF_INET6, &in6, hostname, port);

  switch(conn->ip_version) {
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
    struct ResolverResults *res = NULL;
    free(conn->async.hostname);
    conn->async.hostname = bufp;
    conn->async.port = port;
    conn->async.done = FALSE;   /* not done */
    conn->async.status = 0;     /* clear */
    conn->async.dns = NULL;     /* clear */
    res = calloc(sizeof(struct ResolverResults), 1);
    if(!res) {
      free(conn->async.hostname);
      conn->async.hostname = NULL;
      return NULL;
    }
    conn->async.os_specific = res;

    /* initial status - failed */
    res->last_status = ARES_ENOTFOUND;
#ifdef ENABLE_IPV6 /* CURLRES_IPV6 */
    if(family == PF_UNSPEC) {
      if(Curl_ipv6works()) {
        res->num_pending = 2;

        /* areschannel is already setup in the Curl_open() function */
        ares_gethostbyname((ares_channel)data->state.resolver, hostname,
                            PF_INET, query_completed_cb, conn);
        ares_gethostbyname((ares_channel)data->state.resolver, hostname,
                            PF_INET6, query_completed_cb, conn);
      }
      else {
        res->num_pending = 1;

        /* areschannel is already setup in the Curl_open() function */
        ares_gethostbyname((ares_channel)data->state.resolver, hostname,
                            PF_INET, query_completed_cb, conn);
      }
    }
    else
#endif /* CURLRES_IPV6 */
    {
      res->num_pending = 1;

      /* areschannel is already setup in the Curl_open() function */
      ares_gethostbyname((ares_channel)data->state.resolver, hostname, family,
                         query_completed_cb, conn);
    }

    *waitp = 1; /* expect asynchronous response */
  }
  return NULL; /* no struct yet */
}

CURLcode Curl_set_dns_servers(struct SessionHandle *data,
                              char *servers)
{
  CURLcode result = CURLE_NOT_BUILT_IN;
  int ares_result;

  /* If server is NULL or empty, this would purge all DNS servers
   * from ares library, which will cause any and all queries to fail.
   * So, just return OK if none are configured and don't actually make
   * any changes to c-ares.  This lets c-ares use it's defaults, which
   * it gets from the OS (for instance from /etc/resolv.conf on Linux).
   */
  if(!(servers && servers[0]))
    return CURLE_OK;

#if (ARES_VERSION >= 0x010704)
  ares_result = ares_set_servers_csv(data->state.resolver, servers);
  switch(ares_result) {
  case ARES_SUCCESS:
    result = CURLE_OK;
    break;
  case ARES_ENOMEM:
    result = CURLE_OUT_OF_MEMORY;
    break;
  case ARES_ENOTINITIALIZED:
  case ARES_ENODATA:
  case ARES_EBADSTR:
  default:
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }
#else /* too old c-ares version! */
  (void)data;
  (void)(ares_result);
#endif
  return result;
}

CURLcode Curl_set_dns_interface(struct SessionHandle *data,
                                const char *interf)
{
#if (ARES_VERSION >= 0x010704)
  if(!interf)
    interf = "";

  ares_set_local_dev((ares_channel)data->state.resolver, interf);

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  (void)interf;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_set_dns_local_ip4(struct SessionHandle *data,
                                const char *local_ip4)
{
#if (ARES_VERSION >= 0x010704)
  struct in_addr a4;

  if((!local_ip4) || (local_ip4[0] == 0)) {
    a4.s_addr = 0; /* disabled: do not bind to a specific address */
  }
  else {
    if(Curl_inet_pton(AF_INET, local_ip4, &a4) != 1) {
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  ares_set_local_ip4((ares_channel)data->state.resolver, ntohl(a4.s_addr));

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  (void)local_ip4;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_set_dns_local_ip6(struct SessionHandle *data,
                                const char *local_ip6)
{
#if (ARES_VERSION >= 0x010704) && defined(ENABLE_IPV6)
  unsigned char a6[INET6_ADDRSTRLEN];

  if((!local_ip6) || (local_ip6[0] == 0)) {
    /* disabled: do not bind to a specific address */
    memset(a6, 0, sizeof(a6));
  }
  else {
    if(Curl_inet_pton(AF_INET6, local_ip6, a6) != 1) {
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  ares_set_local_ip6((ares_channel)data->state.resolver, a6);

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  (void)local_ip6;
  return CURLE_NOT_BUILT_IN;
#endif
}
#endif /* CURLRES_ARES */
