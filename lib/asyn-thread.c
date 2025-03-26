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
#include "socketpair.h"

/***********************************************************************
 * Only for threaded name resolves builds
 **********************************************************************/
#ifdef CURLRES_THREADED

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

#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#endif

#ifdef HAVE_GETADDRINFO
#  define RESOLVER_ENOMEM  EAI_MEMORY  /* = WSA_NOT_ENOUGH_MEMORY on Windows */
#else
#  define RESOLVER_ENOMEM  SOCKENOMEM
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "multiif.h"
#include "inet_ntop.h"
#include "curl_threads.h"
#include "connect.h"
#include "strdup.h"

#ifdef USE_ARES
#include <ares.h>
#ifdef USE_HTTPSRR
#define USE_HTTPSRR_ARES  /* the combo */
#endif
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


/*
 * Curl_resolver_global_init()
 * Called from curl_global_init() to initialize global resolver environment.
 * Does nothing here.
 */
int Curl_resolver_global_init(void)
{
  return CURLE_OK;
}

/*
 * Curl_resolver_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 * Does nothing here.
 */
void Curl_resolver_global_cleanup(void)
{
}

/*
 * Curl_resolver_init()
 * Called from curl_easy_init() -> Curl_open() to initialize resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).
 */
CURLcode Curl_resolver_init(struct Curl_easy *easy, void **resolver)
{
  (void)easy;
  (void)resolver;
  return CURLE_OK;
}

/*
 * Curl_resolver_cleanup()
 * Called from curl_easy_cleanup() -> Curl_close() to cleanup resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).
 */
void Curl_resolver_cleanup(void *resolver)
{
  (void)resolver;
}

/*
 * Curl_resolver_duphandle()
 * Called from curl_easy_duphandle() to duplicate resolver URL state-specific
 * environment ('resolver' member of the UrlState structure).
 */
CURLcode Curl_resolver_duphandle(struct Curl_easy *easy, void **to, void *from)
{
  (void)from;
  return Curl_resolver_init(easy, to);
}

static void destroy_async_data(struct Curl_easy *);

/*
 * Cancel all possibly still on-going resolves for this connection.
 */
void Curl_resolver_cancel(struct Curl_easy *data)
{
  destroy_async_data(data);
}

/* This function is used to init a threaded resolve */
static bool init_resolve_thread(struct Curl_easy *data,
                                const char *hostname, int port,
                                const struct addrinfo *hints);


static struct thread_sync_data *conn_thread_sync_data(struct Curl_easy *data)
{
  return &(data->state.async.thdata.tsd);
}

/* Destroy resolver thread synchronization data */
static
void destroy_thread_sync_data(struct thread_sync_data *tsd)
{
  Curl_mutex_destroy(&tsd->mutx);

  free(tsd->hostname);

  if(tsd->res)
    Curl_freeaddrinfo(tsd->res);

#ifndef CURL_DISABLE_SOCKETPAIR
  /*
   * close one end of the socket pair (may be done in resolver thread);
   * the other end (for reading) is always closed in the parent thread.
   */
#ifndef HAVE_EVENTFD
  if(tsd->sock_pair[1] != CURL_SOCKET_BAD) {
    wakeup_close(tsd->sock_pair[1]);
  }
#endif
#endif
  memset(tsd, 0, sizeof(*tsd));
}

/* Initialize resolver thread synchronization data */
static
int init_thread_sync_data(struct thread_data *td,
                          const char *hostname,
                          int port,
                          const struct addrinfo *hints)
{
  struct thread_sync_data *tsd = &td->tsd;

  memset(tsd, 0, sizeof(*tsd));

  td->init = TRUE;
  tsd->port = port;
  /* Treat the request as done until the thread actually starts so any early
   * cleanup gets done properly.
   */
  tsd->done = TRUE;
#ifdef HAVE_GETADDRINFO
  DEBUGASSERT(hints);
  tsd->hints = *hints;
#else
  (void) hints;
#endif

  Curl_mutex_init(&tsd->mutx);

#ifndef CURL_DISABLE_SOCKETPAIR
  /* create socket pair or pipe */
  if(wakeup_create(tsd->sock_pair, FALSE) < 0) {
    tsd->sock_pair[0] = CURL_SOCKET_BAD;
    tsd->sock_pair[1] = CURL_SOCKET_BAD;
    goto err_exit;
  }
#endif
  tsd->sock_error = CURL_ASYNC_SUCCESS;

  /* Copying hostname string because original can be destroyed by parent
   * thread during gethostbyname execution.
   */
  tsd->hostname = strdup(hostname);
  if(!tsd->hostname)
    goto err_exit;

  return 1;

err_exit:
#ifndef CURL_DISABLE_SOCKETPAIR
  if(tsd->sock_pair[0] != CURL_SOCKET_BAD) {
    wakeup_close(tsd->sock_pair[0]);
    tsd->sock_pair[0] = CURL_SOCKET_BAD;
  }
#endif
  destroy_thread_sync_data(tsd);
  return 0;
}

static CURLcode getaddrinfo_complete(struct Curl_easy *data)
{
  struct thread_sync_data *tsd = conn_thread_sync_data(data);
  CURLcode result;

  result = Curl_addrinfo_callback(data, tsd->sock_error, tsd->res);
  /* The tsd->res structure has been copied to async.dns and perhaps the DNS
     cache. Set our copy to NULL so destroy_thread_sync_data does not free it.
  */
  tsd->res = NULL;

  return result;
}


#ifdef HAVE_GETADDRINFO

/*
 * getaddrinfo_thread() resolves a name and then exits.
 *
 * For builds without ARES, but with USE_IPV6, create a resolver thread
 * and wait on it.
 */
static
#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
DWORD
#else
unsigned int
#endif
CURL_STDCALL getaddrinfo_thread(void *arg)
{
  struct thread_data *td = arg;
  struct thread_sync_data *tsd = &td->tsd;
  char service[12];
  int rc;

  msnprintf(service, sizeof(service), "%d", tsd->port);

  rc = Curl_getaddrinfo_ex(tsd->hostname, service, &tsd->hints, &tsd->res);

  if(rc) {
    tsd->sock_error = SOCKERRNO ? SOCKERRNO : rc;
    if(tsd->sock_error == 0)
      tsd->sock_error = RESOLVER_ENOMEM;
  }
  else {
    Curl_addrinfo_set_port(tsd->res, tsd->port);
  }

  Curl_mutex_acquire(&tsd->mutx);
  if(tsd->done) {
    /* too late, gotta clean up the mess */
    Curl_mutex_release(&tsd->mutx);
    destroy_thread_sync_data(tsd);
  }
  else {
#ifndef CURL_DISABLE_SOCKETPAIR
    if(tsd->sock_pair[1] != CURL_SOCKET_BAD) {
#ifdef HAVE_EVENTFD
      const uint64_t buf[1] = { 1 };
#else
      const char buf[1] = { 1 };
#endif
      /* DNS has been resolved, signal client task */
      if(wakeup_write(tsd->sock_pair[1], buf, sizeof(buf)) < 0) {
        /* update sock_erro to errno */
        tsd->sock_error = SOCKERRNO;
      }
    }
#endif
    tsd->done = TRUE;
    Curl_mutex_release(&tsd->mutx);
  }

  return 0;
}

#else /* HAVE_GETADDRINFO */

/*
 * gethostbyname_thread() resolves a name and then exits.
 */
static
#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
DWORD
#else
unsigned int
#endif
CURL_STDCALL gethostbyname_thread(void *arg)
{
  struct thread_data *td = arg;
  struct thread_sync_data *tsd = &td->tsd;

  tsd->res = Curl_ipv4_resolve_r(tsd->hostname, tsd->port);

  if(!tsd->res) {
    tsd->sock_error = SOCKERRNO;
    if(tsd->sock_error == 0)
      tsd->sock_error = RESOLVER_ENOMEM;
  }

  Curl_mutex_acquire(&tsd->mutx);
  if(tsd->done) {
    /* too late, gotta clean up the mess */
    Curl_mutex_release(&tsd->mutx);
    destroy_thread_sync_data(tsd);
  }
  else {
    tsd->done = TRUE;
    Curl_mutex_release(&tsd->mutx);
  }

  return 0;
}

#endif /* HAVE_GETADDRINFO */

/*
 * destroy_async_data() cleans up async resolver data and thread handle.
 */
static void destroy_async_data(struct Curl_easy *data)
{
  struct Curl_async *async = &data->state.async;
  struct thread_data *td = &async->thdata;
  if(td->init) {
    bool done;
#ifndef CURL_DISABLE_SOCKETPAIR
    curl_socket_t sock_rd = td->tsd.sock_pair[0];
#endif

#ifdef USE_HTTPSRR_ARES
    if(td->channel) {
      ares_destroy(td->channel);
      td->channel = NULL;
    }
#endif
    /*
     * if the thread is still blocking in the resolve syscall, detach it and
     * let the thread do the cleanup...
     */
    Curl_mutex_acquire(&td->tsd.mutx);
    done = td->tsd.done;
    td->tsd.done = TRUE;
    Curl_mutex_release(&td->tsd.mutx);

    if(!done) {
      Curl_thread_destroy(td->thread_hnd);
    }
    else {
      if(td->thread_hnd != curl_thread_t_null)
        Curl_thread_join(&td->thread_hnd);

      destroy_thread_sync_data(&td->tsd);
    }
#ifndef CURL_DISABLE_SOCKETPAIR
    /*
     * ensure CURLMOPT_SOCKETFUNCTION fires CURL_POLL_REMOVE
     * before the FD is invalidated to avoid EBADF on EPOLL_CTL_DEL
     */
    Curl_multi_will_close(data, sock_rd);
    wakeup_close(sock_rd);
#endif

    td->init = FALSE;
  }

}

#ifdef USE_HTTPSRR_ARES
static CURLcode resolve_httpsrr(struct Curl_easy *data,
                                struct Curl_async *async)
{
  int status = ares_init_options(&async->thdata.channel, NULL, 0);
  if(status != ARES_SUCCESS)
    return CURLE_FAILED_INIT;

  memset(&async->thdata.hinfo, 0, sizeof(struct Curl_https_rrinfo));
  async->thdata.hinfo.port = -1;
  ares_query_dnsrec(async->thdata.channel,
                    data->conn->host.name, ARES_CLASS_IN,
                    ARES_REC_TYPE_HTTPS,
                    Curl_dnsrec_done_cb, data, NULL);

  return CURLE_OK;
}
#endif

/*
 * init_resolve_thread() starts a new thread that performs the actual
 * resolve. This function returns before the resolve is done.
 *
 * Returns FALSE in case of failure, otherwise TRUE.
 */
static bool init_resolve_thread(struct Curl_easy *data,
                                const char *hostname, int port,
                                const struct addrinfo *hints)
{
  struct thread_data *td = &data->state.async.thdata;
  /* !checksrc! disable ERRNOVAR 1 */
  int err = ENOMEM;
  struct Curl_async *async = &data->state.async;

  async->port = port;
  async->done = FALSE;
  async->dns = NULL;
  td->thread_hnd = curl_thread_t_null;
  td->start = Curl_now();

  if(!init_thread_sync_data(td, hostname, port, hints)) {
    goto errno_exit;
  }

  /* The thread will set this TRUE when complete. */
  td->tsd.done = FALSE;

#ifdef HAVE_GETADDRINFO
  td->thread_hnd = Curl_thread_create(getaddrinfo_thread, td);
#else
  td->thread_hnd = Curl_thread_create(gethostbyname_thread, td);
#endif

  if(td->thread_hnd == curl_thread_t_null) {
    /* The thread never started, so mark it as done here for proper cleanup. */
    td->tsd.done = TRUE;
    err = errno;
    goto err_exit;
  }
#ifdef USE_HTTPSRR_ARES
  if(resolve_httpsrr(data, async))
    infof(data, "Failed HTTPS RR operation");
#endif
  return TRUE;

err_exit:
  destroy_async_data(data);

errno_exit:
  CURL_SETERRNO(err);
  return FALSE;
}

/*
 * 'entry' may be NULL and then no data is returned
 */
static CURLcode thread_wait_resolv(struct Curl_easy *data,
                                   struct Curl_dns_entry **entry,
                                   bool report)
{
  struct thread_data *td;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  td = &data->state.async.thdata;
  DEBUGASSERT(td);
  DEBUGASSERT(td->thread_hnd != curl_thread_t_null);

  /* wait for the thread to resolve the name */
  if(Curl_thread_join(&td->thread_hnd)) {
    if(entry)
      result = getaddrinfo_complete(data);
  }
  else
    DEBUGASSERT(0);

  data->state.async.done = TRUE;

  if(entry)
    *entry = data->state.async.dns;

  if(!data->state.async.dns && report)
    /* a name was not resolved, report error */
    result = Curl_resolver_error(data);

  destroy_async_data(data);

  if(!data->state.async.dns && report)
    connclose(data->conn, "asynch resolve failed");

  return result;
}


/*
 * Until we gain a way to signal the resolver threads to stop early, we must
 * simply wait for them and ignore their results.
 */
void Curl_resolver_kill(struct Curl_easy *data)
{
  struct thread_data *td = &data->state.async.thdata;

  /* If we are still resolving, we must wait for the threads to fully clean up,
     unfortunately. Otherwise, we can simply cancel to clean up any resolver
     data. */
  if((td->thread_hnd != curl_thread_t_null) && !data->set.quick_exit)
    (void)thread_wait_resolv(data, NULL, FALSE);
  else
    Curl_resolver_cancel(data);
}

/*
 * Curl_resolver_wait_resolv()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 *
 * This is the version for resolves-in-a-thread.
 */
CURLcode Curl_resolver_wait_resolv(struct Curl_easy *data,
                                   struct Curl_dns_entry **entry)
{
  return thread_wait_resolv(data, entry, TRUE);
}

/*
 * Curl_resolver_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 */
CURLcode Curl_resolver_is_resolved(struct Curl_easy *data,
                                   struct Curl_dns_entry **entry)
{
  struct thread_data *td = &data->state.async.thdata;
  bool done = FALSE;

  DEBUGASSERT(entry);
  *entry = NULL;

#ifdef USE_HTTPSRR_ARES
  (void)Curl_ares_perform(td->channel, 0); /* ignore errors */
#endif

  Curl_mutex_acquire(&td->tsd.mutx);
  done = td->tsd.done;
  Curl_mutex_release(&td->tsd.mutx);

  if(done) {
    CURLcode result = td->result;
    getaddrinfo_complete(data);

    if(!result && !data->state.async.dns)
      result = Curl_resolver_error(data);

    if(result) {
      destroy_async_data(data);
      return result;
    }
#ifdef USE_HTTPSRR_ARES
    {
      struct Curl_https_rrinfo *lhrr = Curl_httpsrr_dup_move(&td->hinfo);
      if(!lhrr) {
        destroy_async_data(data);
        return CURLE_OUT_OF_MEMORY;
      }
      data->state.async.dns->hinfo = lhrr;
    }
#endif
    destroy_async_data(data);
    *entry = data->state.async.dns;
  }
  else {
    /* poll for name lookup done with exponential backoff up to 250ms */
    /* should be fine even if this converts to 32-bit */
    timediff_t elapsed = Curl_timediff(Curl_now(),
                                       data->progress.t_startsingle);
    if(elapsed < 0)
      elapsed = 0;

    if(td->poll_interval == 0)
      /* Start at 1ms poll interval */
      td->poll_interval = 1;
    else if(elapsed >= td->interval_end)
      /* Back-off exponentially if last interval expired  */
      td->poll_interval *= 2;

    if(td->poll_interval > 250)
      td->poll_interval = 250;

    td->interval_end = elapsed + td->poll_interval;
    Curl_expire(data, td->poll_interval, EXPIRE_ASYNC_NAME);
  }

  return CURLE_OK;
}

int Curl_resolver_getsock(struct Curl_easy *data, curl_socket_t *socks)
{
  int ret_val = 0;
  struct thread_data *td = &data->state.async.thdata;
#if !defined(CURL_DISABLE_SOCKETPAIR) || defined(USE_HTTPSRR_ARES)
  int socketi = 0;
#else
  (void)socks;
#endif

#ifdef USE_HTTPSRR_ARES
  if(td->init && td->channel) {
    ret_val = Curl_ares_getsock(data, td->channel, socks);
    for(socketi = 0; socketi < (MAX_SOCKSPEREASYHANDLE - 1); socketi++)
      if(!ARES_GETSOCK_READABLE(ret_val, socketi) &&
         !ARES_GETSOCK_WRITABLE(ret_val, socketi))
        break;
  }
#endif
#ifndef CURL_DISABLE_SOCKETPAIR
  if(td->init) {
    /* return read fd to client for polling the DNS resolution status */
    socks[socketi] = td->tsd.sock_pair[0];
    ret_val |= GETSOCK_READSOCK(socketi);
  }
  else
#endif
  {
    timediff_t milli;
    timediff_t ms = Curl_timediff(Curl_now(), td->start);
    if(ms < 3)
      milli = 0;
    else if(ms <= 50)
      milli = ms/3;
    else if(ms <= 250)
      milli = 50;
    else
      milli = 200;
    Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
  }

  return ret_val;
}

#ifndef HAVE_GETADDRINFO
/*
 * Curl_getaddrinfo() - for platforms without getaddrinfo
 */
struct Curl_addrinfo *Curl_resolver_getaddrinfo(struct Curl_easy *data,
                                                const char *hostname,
                                                int port,
                                                int *waitp)
{
  *waitp = 0; /* default to synchronous response */

  /* fire up a new resolver thread! */
  if(init_resolve_thread(data, hostname, port, NULL)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(data, "getaddrinfo() thread failed");

  return NULL;
}

#else /* !HAVE_GETADDRINFO */

/*
 * Curl_resolver_getaddrinfo() - for getaddrinfo
 */
struct Curl_addrinfo *Curl_resolver_getaddrinfo(struct Curl_easy *data,
                                                const char *hostname,
                                                int port,
                                                int *waitp)
{
  struct addrinfo hints;
  int pf = PF_INET;
  *waitp = 0; /* default to synchronous response */

#ifdef CURLRES_IPV6
  if((data->conn->ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
    /* The stack seems to be IPv6-enabled */
    if(data->conn->ip_version == CURL_IPRESOLVE_V6)
      pf = PF_INET6;
    else
      pf = PF_UNSPEC;
  }
#endif /* CURLRES_IPV6 */

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = (data->conn->transport == TRNSPRT_TCP) ?
    SOCK_STREAM : SOCK_DGRAM;

  /* fire up a new resolver thread! */
  if(init_resolve_thread(data, hostname, port, &hints)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(data, "getaddrinfo() thread failed to start");
  return NULL;

}

#endif /* !HAVE_GETADDRINFO */

CURLcode Curl_set_dns_servers(struct Curl_easy *data,
                              char *servers)
{
  (void)data;
  (void)servers;
  return CURLE_NOT_BUILT_IN;

}

CURLcode Curl_set_dns_interface(struct Curl_easy *data,
                                const char *interf)
{
  (void)data;
  (void)interf;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_set_dns_local_ip4(struct Curl_easy *data,
                                const char *local_ip4)
{
  (void)data;
  (void)local_ip4;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_set_dns_local_ip6(struct Curl_easy *data,
                                const char *local_ip6)
{
  (void)data;
  (void)local_ip6;
  return CURLE_NOT_BUILT_IN;
}

#endif /* CURLRES_THREADED */
