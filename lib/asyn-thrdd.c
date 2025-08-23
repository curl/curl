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
#include "cfilters.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "multiif.h"
#include "curl_threads.h"
#include "select.h"
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
 * Curl_async_global_init()
 * Called from curl_global_init() to initialize global resolver environment.
 * Does nothing here.
 */
int Curl_async_global_init(void)
{
#if defined(USE_ARES) && defined(CARES_HAVE_ARES_LIBRARY_INIT)
  if(ares_library_init(ARES_LIB_INIT_ALL)) {
    return CURLE_FAILED_INIT;
  }
#endif
  return CURLE_OK;
}

/*
 * Curl_async_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 * Does nothing here.
 */
void Curl_async_global_cleanup(void)
{
#if defined(USE_ARES) && defined(CARES_HAVE_ARES_LIBRARY_INIT)
  ares_library_cleanup();
#endif
}

static void async_thrdd_destroy(struct Curl_easy *);
static void async_thrdd_shutdown(struct Curl_easy *);

CURLcode Curl_async_get_impl(struct Curl_easy *data, void **impl)
{
  (void)data;
  *impl = NULL;
  return CURLE_OK;
}

/* Give up reference to add_ctx */
static void addr_ctx_unlink(struct async_thrdd_addr_ctx **paddr_ctx,
                            struct Curl_easy *data)
{
  struct async_thrdd_addr_ctx *addr_ctx = *paddr_ctx;
  bool destroy;

  (void)data;
  if(!addr_ctx)
    return;

  Curl_mutex_acquire(&addr_ctx->mutx);
  if(!data)  /* called by resolving thread */
    addr_ctx->thrd_done = TRUE;

  DEBUGASSERT(addr_ctx->ref_count);
  --addr_ctx->ref_count;
  destroy = !addr_ctx->ref_count;
  Curl_mutex_release(&addr_ctx->mutx);

  if(destroy) {
    Curl_mutex_destroy(&addr_ctx->mutx);
    free(addr_ctx->hostname);
    if(addr_ctx->res)
      Curl_freeaddrinfo(addr_ctx->res);
#ifndef CURL_DISABLE_SOCKETPAIR
#ifndef USE_EVENTFD
    wakeup_close(addr_ctx->sock_pair[1]);
#endif
    wakeup_close(addr_ctx->sock_pair[0]);
#endif
    free(addr_ctx);
  }
  *paddr_ctx = NULL;
}

/* Initialize context for threaded resolver */
static struct async_thrdd_addr_ctx *
addr_ctx_create(struct Curl_easy *data,
                const char *hostname, int port,
                const struct addrinfo *hints)
{
  struct async_thrdd_addr_ctx *addr_ctx = calloc(1, sizeof(*addr_ctx));
  if(!addr_ctx)
    return NULL;

  addr_ctx->thread_hnd = curl_thread_t_null;
  addr_ctx->port = port;
  addr_ctx->ref_count = 1;

#ifdef HAVE_GETADDRINFO
  DEBUGASSERT(hints);
  addr_ctx->hints = *hints;
#else
  (void)hints;
#endif

  Curl_mutex_init(&addr_ctx->mutx);

#ifndef CURL_DISABLE_SOCKETPAIR
  /* create socket pair or pipe */
  if(wakeup_create(addr_ctx->sock_pair, FALSE) < 0) {
    addr_ctx->sock_pair[0] = CURL_SOCKET_BAD;
    addr_ctx->sock_pair[1] = CURL_SOCKET_BAD;
    goto err_exit;
  }
#endif
  addr_ctx->sock_error = 0;

  /* Copying hostname string because original can be destroyed by parent
   * thread during gethostbyname execution.
   */
  addr_ctx->hostname = strdup(hostname);
  if(!addr_ctx->hostname)
    goto err_exit;

  return addr_ctx;

err_exit:
  addr_ctx_unlink(&addr_ctx, data);
  return NULL;
}

static void async_thrd_cleanup(void *arg)
{
  struct async_thrdd_addr_ctx *addr_ctx = arg;

  Curl_thread_disable_cancel();
  addr_ctx_unlink(&addr_ctx, NULL);
}

#ifdef HAVE_GETADDRINFO

/*
 * getaddrinfo_thread() resolves a name and then exits.
 *
 * For builds without ARES, but with USE_IPV6, create a resolver thread
 * and wait on it.
 */
static CURL_THREAD_RETURN_T CURL_STDCALL getaddrinfo_thread(void *arg)
{
  struct async_thrdd_addr_ctx *addr_ctx = arg;
  bool do_abort;

/* clang complains about empty statements and the pthread_cleanup* macros
 * are pretty ill defined. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra-semi-stmt"
#endif

  Curl_thread_push_cleanup(async_thrd_cleanup, addr_ctx);

  Curl_mutex_acquire(&addr_ctx->mutx);
  do_abort = addr_ctx->do_abort;
  Curl_mutex_release(&addr_ctx->mutx);

  if(!do_abort) {
    char service[12];
    int rc;

#ifdef DEBUGBUILD
    Curl_resolve_test_delay();
#endif
    msnprintf(service, sizeof(service), "%d", addr_ctx->port);

    rc = Curl_getaddrinfo_ex(addr_ctx->hostname, service,
                             &addr_ctx->hints, &addr_ctx->res);

    if(rc) {
      addr_ctx->sock_error = SOCKERRNO ? SOCKERRNO : rc;
      if(addr_ctx->sock_error == 0)
        addr_ctx->sock_error = RESOLVER_ENOMEM;
    }
    else {
      Curl_addrinfo_set_port(addr_ctx->res, addr_ctx->port);
    }

    Curl_mutex_acquire(&addr_ctx->mutx);
    do_abort = addr_ctx->do_abort;
    Curl_mutex_release(&addr_ctx->mutx);
#ifndef CURL_DISABLE_SOCKETPAIR
    if(!do_abort) {
#ifdef USE_EVENTFD
      const uint64_t buf[1] = { 1 };
#else
      const char buf[1] = { 1 };
#endif
      /* Thread is done, notify transfer */
      if(wakeup_write(addr_ctx->sock_pair[1], buf, sizeof(buf)) < 0) {
        /* update sock_error to errno */
        addr_ctx->sock_error = SOCKERRNO;
      }
    }
#endif

  }

  Curl_thread_pop_cleanup();
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

  addr_ctx_unlink(&addr_ctx, NULL);
  return 0;
}

#else /* HAVE_GETADDRINFO */

/*
 * gethostbyname_thread() resolves a name and then exits.
 */
static CURL_THREAD_RETURN_T CURL_STDCALL gethostbyname_thread(void *arg)
{
  struct async_thrdd_addr_ctx *addr_ctx = arg;
  bool do_abort;

/* clang complains about empty statements and the pthread_cleanup* macros
 * are pretty ill defined. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra-semi-stmt"
#endif

  Curl_thread_push_cleanup(async_thrd_cleanup, addr_ctx);

  Curl_mutex_acquire(&addr_ctx->mutx);
  do_abort = addr_ctx->do_abort;
  Curl_mutex_release(&addr_ctx->mutx);

  if(!do_abort) {
#ifdef DEBUGBUILD
    Curl_resolve_test_delay();
#endif

    addr_ctx->res = Curl_ipv4_resolve_r(addr_ctx->hostname, addr_ctx->port);
    if(!addr_ctx->res) {
      addr_ctx->sock_error = SOCKERRNO;
      if(addr_ctx->sock_error == 0)
        addr_ctx->sock_error = RESOLVER_ENOMEM;
    }

    Curl_mutex_acquire(&addr_ctx->mutx);
    do_abort = addr_ctx->do_abort;
    Curl_mutex_release(&addr_ctx->mutx);
#ifndef CURL_DISABLE_SOCKETPAIR
    if(!do_abort) {
#ifdef USE_EVENTFD
      const uint64_t buf[1] = { 1 };
#else
      const char buf[1] = { 1 };
#endif
      /* Thread is done, notify transfer */
      if(wakeup_write(addr_ctx->sock_pair[1], buf, sizeof(buf)) < 0) {
        /* update sock_error to errno */
        addr_ctx->sock_error = SOCKERRNO;
      }
    }
#endif
  }

  Curl_thread_pop_cleanup();
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

  async_thrd_cleanup(addr_ctx);
  return 0;
}

#endif /* HAVE_GETADDRINFO */

/*
 * async_thrdd_destroy() cleans up async resolver data and thread handle.
 */
static void async_thrdd_destroy(struct Curl_easy *data)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  struct async_thrdd_addr_ctx *addr = thrdd->addr;

#ifdef USE_HTTPSRR_ARES
  if(thrdd->rr.channel) {
    ares_destroy(thrdd->rr.channel);
    thrdd->rr.channel = NULL;
  }
  Curl_httpsrr_cleanup(&thrdd->rr.hinfo);
#endif

  if(thrdd->addr && (thrdd->addr->thread_hnd != curl_thread_t_null)) {
    bool done;

    Curl_mutex_acquire(&addr->mutx);
#ifndef CURL_DISABLE_SOCKETPAIR
    if(!addr->do_abort)
      Curl_multi_will_close(data, addr->sock_pair[0]);
#endif
    addr->do_abort = TRUE;
    done = addr->thrd_done;
    Curl_mutex_release(&addr->mutx);

    if(done) {
      Curl_thread_join(&addr->thread_hnd);
      CURL_TRC_DNS(data, "async_thrdd_destroy, thread joined");
    }
    else {
      /* thread is still running. Detach the thread while mutexed, it will
       * trigger the cleanup when it releases its reference. */
      Curl_thread_destroy(&addr->thread_hnd);
      CURL_TRC_DNS(data, "async_thrdd_destroy, thread detached");
    }
  }
  addr_ctx_unlink(&thrdd->addr, data);
}

#ifdef USE_HTTPSRR_ARES

static void async_thrdd_rr_done(void *user_data, ares_status_t status,
                                size_t timeouts,
                                const ares_dns_record_t *dnsrec)
{
  struct Curl_easy *data = user_data;
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;

  (void)timeouts;
  thrdd->rr.done = TRUE;
  if((ARES_SUCCESS != status) || !dnsrec)
    return;
  thrdd->rr.result = Curl_httpsrr_from_ares(data, dnsrec, &thrdd->rr.hinfo);
}

static CURLcode async_rr_start(struct Curl_easy *data)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  int status;

  DEBUGASSERT(!thrdd->rr.channel);
  status = ares_init_options(&thrdd->rr.channel, NULL, 0);
  if(status != ARES_SUCCESS) {
    thrdd->rr.channel = NULL;
    return CURLE_FAILED_INIT;
  }
#ifdef CURLDEBUG
  if(getenv("CURL_DNS_SERVER")) {
    const char *servers = getenv("CURL_DNS_SERVER");
    status = ares_set_servers_ports_csv(thrdd->rr.channel, servers);
    if(status)
      return CURLE_FAILED_INIT;
  }
#endif

  memset(&thrdd->rr.hinfo, 0, sizeof(thrdd->rr.hinfo));
  thrdd->rr.hinfo.port = -1;
  ares_query_dnsrec(thrdd->rr.channel,
                    data->conn->host.name, ARES_CLASS_IN,
                    ARES_REC_TYPE_HTTPS,
                    async_thrdd_rr_done, data, NULL);
  CURL_TRC_DNS(data, "Issued HTTPS-RR request for %s", data->conn->host.name);
  return CURLE_OK;
}
#endif

/*
 * async_thrdd_init() starts a new thread that performs the actual
 * resolve. This function returns before the resolve is done.
 *
 * Returns FALSE in case of failure, otherwise TRUE.
 */
static bool async_thrdd_init(struct Curl_easy *data,
                             const char *hostname, int port, int ip_version,
                             const struct addrinfo *hints)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  struct async_thrdd_addr_ctx *addr_ctx;

  /* !checksrc! disable ERRNOVAR 1 */
  int err = ENOMEM;

  if(thrdd->addr
#ifdef USE_HTTPSRR_ARES
     || thrdd->rr.channel
#endif
     ) {
    CURL_TRC_DNS(data, "starting new resolve, with previous not cleaned up");
    async_thrdd_destroy(data);
    DEBUGASSERT(!thrdd->addr);
#ifdef USE_HTTPSRR_ARES
    DEBUGASSERT(!thrdd->rr.channel);
#endif
  }

  data->state.async.dns = NULL;
  data->state.async.done = FALSE;
  data->state.async.port = port;
  data->state.async.ip_version = ip_version;
  free(data->state.async.hostname);
  data->state.async.hostname = strdup(hostname);
  if(!data->state.async.hostname)
    goto err_exit;

  addr_ctx = addr_ctx_create(data, hostname, port, hints);
  if(!addr_ctx)
    goto err_exit;
  thrdd->addr = addr_ctx;

  /* passing addr_ctx to the thread adds a reference */
  addr_ctx->ref_count = 2;
  addr_ctx->start = curlx_now();

#ifdef HAVE_GETADDRINFO
  addr_ctx->thread_hnd = Curl_thread_create(getaddrinfo_thread, addr_ctx);
#else
  addr_ctx->thread_hnd = Curl_thread_create(gethostbyname_thread, addr_ctx);
#endif

  if(addr_ctx->thread_hnd == curl_thread_t_null) {
    /* The thread never started */
    addr_ctx->ref_count = 1;
    addr_ctx->thrd_done = TRUE;
    err = errno;
    goto err_exit;
  }

#ifdef USE_HTTPSRR_ARES
  if(async_rr_start(data))
    infof(data, "Failed HTTPS RR operation");
#endif
  CURL_TRC_DNS(data, "resolve thread started for of %s:%d", hostname, port);
  return TRUE;

err_exit:
  CURL_TRC_DNS(data, "resolve thread failed init: %d", err);
  async_thrdd_destroy(data);
  CURL_SETERRNO(err);
  return FALSE;
}

static void async_thrdd_shutdown(struct Curl_easy *data)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  struct async_thrdd_addr_ctx *addr_ctx = thrdd->addr;
  bool done;

  if(!addr_ctx)
    return;
  if(addr_ctx->thread_hnd == curl_thread_t_null)
    return;

  Curl_mutex_acquire(&addr_ctx->mutx);
#ifndef CURL_DISABLE_SOCKETPAIR
    if(!addr_ctx->do_abort)
      Curl_multi_will_close(data, addr_ctx->sock_pair[0]);
#endif
  addr_ctx->do_abort = TRUE;
  done = addr_ctx->thrd_done;
  Curl_mutex_release(&addr_ctx->mutx);

  DEBUGASSERT(addr_ctx->thread_hnd != curl_thread_t_null);
  if(!done && (addr_ctx->thread_hnd != curl_thread_t_null)) {
    CURL_TRC_DNS(data, "cancelling resolve thread");
    (void)Curl_thread_cancel(&addr_ctx->thread_hnd);
  }
}

/*
 * 'entry' may be NULL and then no data is returned
 */
static CURLcode asyn_thrdd_await(struct Curl_easy *data,
                                 struct async_thrdd_addr_ctx *addr_ctx,
                                 struct Curl_dns_entry **entry)
{
  CURLcode result = CURLE_OK;

  if(addr_ctx->thread_hnd != curl_thread_t_null) {
    /* not interested in result? cancel, if still running... */
    if(!entry)
      async_thrdd_shutdown(data);

    CURL_TRC_DNS(data, "resolve, wait for thread to finish");
    if(!Curl_thread_join(&addr_ctx->thread_hnd)) {
      DEBUGASSERT(0);
    }

    if(entry)
      result = Curl_async_is_resolved(data, entry);
  }

  data->state.async.done = TRUE;
  if(entry)
    *entry = data->state.async.dns;

  return result;
}

/*
 * Until we gain a way to signal the resolver threads to stop early, we must
 * simply wait for them and ignore their results.
 */
void Curl_async_thrdd_shutdown(struct Curl_easy *data)
{
  async_thrdd_shutdown(data);
}

void Curl_async_thrdd_destroy(struct Curl_easy *data)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;

  if(thrdd->addr && !data->set.quick_exit) {
    (void)asyn_thrdd_await(data, thrdd->addr, NULL);
  }
  async_thrdd_destroy(data);
}

/*
 * Curl_async_await()
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
CURLcode Curl_async_await(struct Curl_easy *data,
                          struct Curl_dns_entry **entry)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  if(thrdd->addr)
    return asyn_thrdd_await(data, thrdd->addr, entry);
  return CURLE_FAILED_INIT;
}

/*
 * Curl_async_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 */
CURLcode Curl_async_is_resolved(struct Curl_easy *data,
                                struct Curl_dns_entry **dns)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  bool done = FALSE;

  DEBUGASSERT(dns);
  *dns = NULL;

  if(data->state.async.done) {
    *dns = data->state.async.dns;
    CURL_TRC_DNS(data, "threaded: is_resolved(), already done, dns=%sfound",
                 *dns ? "" : "not ");
    return CURLE_OK;
  }

#ifdef USE_HTTPSRR_ARES
  /* best effort, ignore errors */
  if(thrdd->rr.channel)
    (void)Curl_ares_perform(thrdd->rr.channel, 0);
#endif

  DEBUGASSERT(thrdd->addr);
  if(!thrdd->addr)
    return CURLE_FAILED_INIT;

  Curl_mutex_acquire(&thrdd->addr->mutx);
  done = thrdd->addr->thrd_done;
  Curl_mutex_release(&thrdd->addr->mutx);

  if(done) {
    CURLcode result = CURLE_OK;

    data->state.async.done = TRUE;
    Curl_resolv_unlink(data, &data->state.async.dns);

    if(thrdd->addr->res) {
      data->state.async.dns =
        Curl_dnscache_mk_entry(data, thrdd->addr->res,
                               data->state.async.hostname, 0,
                               data->state.async.port, FALSE);
      thrdd->addr->res = NULL;
      if(!data->state.async.dns)
        result = CURLE_OUT_OF_MEMORY;

#ifdef USE_HTTPSRR_ARES
      if(thrdd->rr.channel) {
        result = thrdd->rr.result;
        if(!result) {
          struct Curl_https_rrinfo *lhrr;
          lhrr = Curl_httpsrr_dup_move(&thrdd->rr.hinfo);
          if(!lhrr)
            result = CURLE_OUT_OF_MEMORY;
          else
            data->state.async.dns->hinfo = lhrr;
        }
      }
#endif
      if(!result && data->state.async.dns)
        result = Curl_dnscache_add(data, data->state.async.dns);
    }

    if(!result && !data->state.async.dns)
      result = Curl_resolver_error(data, NULL);
    if(result)
      Curl_resolv_unlink(data, &data->state.async.dns);
    *dns = data->state.async.dns;
    CURL_TRC_DNS(data, "is_resolved() result=%d, dns=%sfound",
                 result, *dns ? "" : "not ");
    async_thrdd_shutdown(data);
    return result;
  }
  else {
    /* poll for name lookup done with exponential backoff up to 250ms */
    /* should be fine even if this converts to 32-bit */
    timediff_t elapsed = curlx_timediff(curlx_now(),
                                       data->progress.t_startsingle);
    if(elapsed < 0)
      elapsed = 0;

    if(thrdd->addr->poll_interval == 0)
      /* Start at 1ms poll interval */
      thrdd->addr->poll_interval = 1;
    else if(elapsed >= thrdd->addr->interval_end)
      /* Back-off exponentially if last interval expired  */
      thrdd->addr->poll_interval *= 2;

    if(thrdd->addr->poll_interval > 250)
      thrdd->addr->poll_interval = 250;

    thrdd->addr->interval_end = elapsed + thrdd->addr->poll_interval;
    Curl_expire(data, thrdd->addr->poll_interval, EXPIRE_ASYNC_NAME);
    return CURLE_OK;
  }
}

CURLcode Curl_async_pollset(struct Curl_easy *data, struct easy_pollset *ps)
{
  struct async_thrdd_ctx *thrdd = &data->state.async.thrdd;
  CURLcode result = CURLE_OK;
  bool thrd_done;

#if !defined(USE_HTTPSRR_ARES) && defined(CURL_DISABLE_SOCKETPAIR)
  (void)ps;
#endif

#ifdef USE_HTTPSRR_ARES
  if(thrdd->rr.channel) {
    result = Curl_ares_pollset(data, thrdd->rr.channel, ps);
    if(result)
      return result;
  }
#endif
  if(!thrdd->addr)
    return result;

  Curl_mutex_acquire(&thrdd->addr->mutx);
  thrd_done = thrdd->addr->thrd_done;
  Curl_mutex_release(&thrdd->addr->mutx);

  if(!thrd_done) {
#ifndef CURL_DISABLE_SOCKETPAIR
  /* return read fd to client for polling the DNS resolution status */
    result = Curl_pollset_add_in(data, ps, thrdd->addr->sock_pair[0]);
#else
    timediff_t milli;
    timediff_t ms = curlx_timediff(curlx_now(), thrdd->addr->start);
    if(ms < 3)
      milli = 0;
    else if(ms <= 50)
      milli = ms/3;
    else if(ms <= 250)
      milli = 50;
    else
      milli = 200;
    Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
#endif
  }
  return result;
}

#ifndef HAVE_GETADDRINFO
/*
 * Curl_async_getaddrinfo() - for platforms without getaddrinfo
 */
struct Curl_addrinfo *Curl_async_getaddrinfo(struct Curl_easy *data,
                                             const char *hostname,
                                             int port,
                                             int ip_version,
                                             int *waitp)
{
  (void)ip_version;
  *waitp = 0; /* default to synchronous response */

  /* fire up a new resolver thread! */
  if(async_thrdd_init(data, hostname, port, ip_version, NULL)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(data, "getaddrinfo() thread failed");

  return NULL;
}

#else /* !HAVE_GETADDRINFO */

/*
 * Curl_async_getaddrinfo() - for getaddrinfo
 */
struct Curl_addrinfo *Curl_async_getaddrinfo(struct Curl_easy *data,
                                             const char *hostname,
                                             int port,
                                             int ip_version,
                                             int *waitp)
{
  struct addrinfo hints;
  int pf = PF_INET;
  *waitp = 0; /* default to synchronous response */

  CURL_TRC_DNS(data, "init threaded resolve of %s:%d", hostname, port);
#ifdef CURLRES_IPV6
  if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
    /* The stack seems to be IPv6-enabled */
    if(ip_version == CURL_IPRESOLVE_V6)
      pf = PF_INET6;
    else
      pf = PF_UNSPEC;
  }
#else
  (void)ip_version;
#endif /* CURLRES_IPV6 */

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype =
    (Curl_conn_get_transport(data, data->conn) == TRNSPRT_TCP) ?
    SOCK_STREAM : SOCK_DGRAM;

  /* fire up a new resolver thread! */
  if(async_thrdd_init(data, hostname, port, ip_version, &hints)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(data, "getaddrinfo() thread failed to start");
  return NULL;

}

#endif /* !HAVE_GETADDRINFO */

#endif /* CURLRES_THREADED */
