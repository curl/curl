/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#if defined(USE_THREADS_POSIX)
#  ifdef HAVE_PTHREAD_H
#    include <pthread.h>
#  endif
#elif defined(USE_THREADS_WIN32)
#  ifdef HAVE_PROCESS_H
#    include <process.h>
#  endif
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#ifdef HAVE_GETADDRINFO
#  define RESOLVER_ENOMEM  EAI_MEMORY
#else
#  define RESOLVER_ENOMEM  ENOMEM
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"
#include "multiif.h"
#include "inet_ntop.h"
#include "curl_threads.h"
#include "connect.h"
#include "socketpair.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

struct resdata {
  struct curltime start;
};

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
  *resolver = calloc(1, sizeof(struct resdata));
  if(!*resolver)
    return CURLE_OUT_OF_MEMORY;
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
  free(resolver);
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

static void destroy_async_data(struct Curl_async *);

/*
 * Cancel all possibly still on-going resolves for this connection.
 */
void Curl_resolver_cancel(struct connectdata *conn)
{
  destroy_async_data(&conn->async);
}

/* This function is used to init a threaded resolve */
static bool init_resolve_thread(struct connectdata *conn,
                                const char *hostname, int port,
                                const struct addrinfo *hints);


/* Data for synchronization between resolver thread and its parent */
struct thread_sync_data {
  curl_mutex_t * mtx;
  int done;

  char *hostname;        /* hostname to resolve, Curl_async.hostname
                            duplicate */
  int port;
#ifdef USE_SOCKETPAIR
  struct connectdata *conn;
  curl_socket_t sock_pair[2]; /* socket pair */
#endif
  int sock_error;
  Curl_addrinfo *res;
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints;
#endif
  struct thread_data *td; /* for thread-self cleanup */
};

struct thread_data {
  curl_thread_t thread_hnd;
  unsigned int poll_interval;
  time_t interval_end;
  struct thread_sync_data tsd;
};

static struct thread_sync_data *conn_thread_sync_data(struct connectdata *conn)
{
  return &(((struct thread_data *)conn->async.os_specific)->tsd);
}

/* Destroy resolver thread synchronization data */
static
void destroy_thread_sync_data(struct thread_sync_data * tsd)
{
  if(tsd->mtx) {
    Curl_mutex_destroy(tsd->mtx);
    free(tsd->mtx);
  }

  free(tsd->hostname);

  if(tsd->res)
    Curl_freeaddrinfo(tsd->res);

#ifdef USE_SOCKETPAIR
  /*
   * close one end of the socket pair (may be done in resolver thread);
   * the other end (for reading) is always closed in the parent thread.
   */
  if(tsd->sock_pair[1] != CURL_SOCKET_BAD) {
    sclose(tsd->sock_pair[1]);
  }
#endif
  memset(tsd, 0, sizeof(*tsd));
}

/* Initialize resolver thread synchronization data */
static
int init_thread_sync_data(struct thread_data * td,
                           const char *hostname,
                           int port,
                           const struct addrinfo *hints)
{
  struct thread_sync_data *tsd = &td->tsd;

  memset(tsd, 0, sizeof(*tsd));

  tsd->td = td;
  tsd->port = port;
  /* Treat the request as done until the thread actually starts so any early
   * cleanup gets done properly.
   */
  tsd->done = 1;
#ifdef HAVE_GETADDRINFO
  DEBUGASSERT(hints);
  tsd->hints = *hints;
#else
  (void) hints;
#endif

  tsd->mtx = malloc(sizeof(curl_mutex_t));
  if(tsd->mtx == NULL)
    goto err_exit;

  Curl_mutex_init(tsd->mtx);

#ifdef USE_SOCKETPAIR
  /* create socket pair, avoid AF_LOCAL since it doesn't build on Solaris */
  if(Curl_socketpair(AF_UNIX, SOCK_STREAM, 0, &tsd->sock_pair[0]) < 0) {
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
  /* Memory allocation failed */
  destroy_thread_sync_data(tsd);
  return 0;
}

static int getaddrinfo_complete(struct connectdata *conn)
{
  struct thread_sync_data *tsd = conn_thread_sync_data(conn);
  int rc;

  rc = Curl_addrinfo_callback(conn, tsd->sock_error, tsd->res);
  /* The tsd->res structure has been copied to async.dns and perhaps the DNS
     cache.  Set our copy to NULL so destroy_thread_sync_data doesn't free it.
  */
  tsd->res = NULL;

  return rc;
}


#ifdef HAVE_GETADDRINFO

/*
 * getaddrinfo_thread() resolves a name and then exits.
 *
 * For builds without ARES, but with ENABLE_IPV6, create a resolver thread
 * and wait on it.
 */
static unsigned int CURL_STDCALL getaddrinfo_thread(void *arg)
{
  struct thread_sync_data *tsd = (struct thread_sync_data*)arg;
  struct thread_data *td = tsd->td;
  char service[12];
  int rc;
#ifdef USE_SOCKETPAIR
  char buf[1];
#endif

  msnprintf(service, sizeof(service), "%d", tsd->port);

  rc = Curl_getaddrinfo_ex(tsd->hostname, service, &tsd->hints, &tsd->res);

  if(rc != 0) {
    tsd->sock_error = SOCKERRNO?SOCKERRNO:rc;
    if(tsd->sock_error == 0)
      tsd->sock_error = RESOLVER_ENOMEM;
  }
  else {
    Curl_addrinfo_set_port(tsd->res, tsd->port);
  }

  Curl_mutex_acquire(tsd->mtx);
  if(tsd->done) {
    /* too late, gotta clean up the mess */
    Curl_mutex_release(tsd->mtx);
    destroy_thread_sync_data(tsd);
    free(td);
  }
  else {
#ifdef USE_SOCKETPAIR
    if(tsd->sock_pair[1] != CURL_SOCKET_BAD) {
      /* DNS has been resolved, signal client task */
      buf[0] = 1;
      if(swrite(tsd->sock_pair[1],  buf, sizeof(buf)) < 0) {
        /* update sock_erro to errno */
        tsd->sock_error = SOCKERRNO;
      }
    }
#endif
    tsd->done = 1;
    Curl_mutex_release(tsd->mtx);
  }

  return 0;
}

#else /* HAVE_GETADDRINFO */

/*
 * gethostbyname_thread() resolves a name and then exits.
 */
static unsigned int CURL_STDCALL gethostbyname_thread(void *arg)
{
  struct thread_sync_data *tsd = (struct thread_sync_data *)arg;
  struct thread_data *td = tsd->td;

  tsd->res = Curl_ipv4_resolve_r(tsd->hostname, tsd->port);

  if(!tsd->res) {
    tsd->sock_error = SOCKERRNO;
    if(tsd->sock_error == 0)
      tsd->sock_error = RESOLVER_ENOMEM;
  }

  Curl_mutex_acquire(tsd->mtx);
  if(tsd->done) {
    /* too late, gotta clean up the mess */
    Curl_mutex_release(tsd->mtx);
    destroy_thread_sync_data(tsd);
    free(td);
  }
  else {
    tsd->done = 1;
    Curl_mutex_release(tsd->mtx);
  }

  return 0;
}

#endif /* HAVE_GETADDRINFO */

/*
 * destroy_async_data() cleans up async resolver data and thread handle.
 */
static void destroy_async_data(struct Curl_async *async)
{
  if(async->os_specific) {
    struct thread_data *td = (struct thread_data*) async->os_specific;
    int done;
#ifdef USE_SOCKETPAIR
    curl_socket_t sock_rd = td->tsd.sock_pair[0];
    struct connectdata *conn = td->tsd.conn;
#endif

    /*
     * if the thread is still blocking in the resolve syscall, detach it and
     * let the thread do the cleanup...
     */
    Curl_mutex_acquire(td->tsd.mtx);
    done = td->tsd.done;
    td->tsd.done = 1;
    Curl_mutex_release(td->tsd.mtx);

    if(!done) {
      Curl_thread_destroy(td->thread_hnd);
    }
    else {
      if(td->thread_hnd != curl_thread_t_null)
        Curl_thread_join(&td->thread_hnd);

      destroy_thread_sync_data(&td->tsd);

      free(async->os_specific);
    }
#ifdef USE_SOCKETPAIR
    /*
     * ensure CURLMOPT_SOCKETFUNCTION fires CURL_POLL_REMOVE
     * before the FD is invalidated to avoid EBADF on EPOLL_CTL_DEL
     */
    if(conn)
      Curl_multi_closed(conn->data, sock_rd);
    sclose(sock_rd);
#endif
  }
  async->os_specific = NULL;

  free(async->hostname);
  async->hostname = NULL;
}

/*
 * init_resolve_thread() starts a new thread that performs the actual
 * resolve. This function returns before the resolve is done.
 *
 * Returns FALSE in case of failure, otherwise TRUE.
 */
static bool init_resolve_thread(struct connectdata *conn,
                                const char *hostname, int port,
                                const struct addrinfo *hints)
{
  struct thread_data *td = calloc(1, sizeof(struct thread_data));
  int err = ENOMEM;

  conn->async.os_specific = (void *)td;
  if(!td)
    goto errno_exit;

  conn->async.port = port;
  conn->async.done = FALSE;
  conn->async.status = 0;
  conn->async.dns = NULL;
  td->thread_hnd = curl_thread_t_null;

  if(!init_thread_sync_data(td, hostname, port, hints)) {
    conn->async.os_specific = NULL;
    free(td);
    goto errno_exit;
  }

  free(conn->async.hostname);
  conn->async.hostname = strdup(hostname);
  if(!conn->async.hostname)
    goto err_exit;

  /* The thread will set this to 1 when complete. */
  td->tsd.done = 0;

#ifdef HAVE_GETADDRINFO
  td->thread_hnd = Curl_thread_create(getaddrinfo_thread, &td->tsd);
#else
  td->thread_hnd = Curl_thread_create(gethostbyname_thread, &td->tsd);
#endif

  if(!td->thread_hnd) {
    /* The thread never started, so mark it as done here for proper cleanup. */
    td->tsd.done = 1;
    err = errno;
    goto err_exit;
  }

  return TRUE;

 err_exit:
  destroy_async_data(&conn->async);

 errno_exit:
  errno = err;
  return FALSE;
}

/*
 * resolver_error() calls failf() with the appropriate message after a resolve
 * error
 */

static CURLcode resolver_error(struct connectdata *conn)
{
  const char *host_or_proxy;
  CURLcode result;

  if(conn->bits.httpproxy) {
    host_or_proxy = "proxy";
    result = CURLE_COULDNT_RESOLVE_PROXY;
  }
  else {
    host_or_proxy = "host";
    result = CURLE_COULDNT_RESOLVE_HOST;
  }

  failf(conn->data, "Could not resolve %s: %s", host_or_proxy,
        conn->async.hostname);

  return result;
}

static CURLcode thread_wait_resolv(struct connectdata *conn,
                                   struct Curl_dns_entry **entry,
                                   bool report)
{
  struct thread_data   *td = (struct thread_data*) conn->async.os_specific;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(conn && td);
  DEBUGASSERT(td->thread_hnd != curl_thread_t_null);

  /* wait for the thread to resolve the name */
  if(Curl_thread_join(&td->thread_hnd)) {
    if(entry)
      result = getaddrinfo_complete(conn);
  }
  else
    DEBUGASSERT(0);

  conn->async.done = TRUE;

  if(entry)
    *entry = conn->async.dns;

  if(!conn->async.dns && report)
    /* a name was not resolved, report error */
    result = resolver_error(conn);

  destroy_async_data(&conn->async);

  if(!conn->async.dns && report)
    connclose(conn, "asynch resolve failed");

  return result;
}


/*
 * Until we gain a way to signal the resolver threads to stop early, we must
 * simply wait for them and ignore their results.
 */
void Curl_resolver_kill(struct connectdata *conn)
{
  struct thread_data *td = (struct thread_data*) conn->async.os_specific;

  /* If we're still resolving, we must wait for the threads to fully clean up,
     unfortunately.  Otherwise, we can simply cancel to clean up any resolver
     data. */
  if(td && td->thread_hnd != curl_thread_t_null)
    (void)thread_wait_resolv(conn, NULL, FALSE);
  else
    Curl_resolver_cancel(conn);
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
CURLcode Curl_resolver_wait_resolv(struct connectdata *conn,
                                   struct Curl_dns_entry **entry)
{
  return thread_wait_resolv(conn, entry, TRUE);
}

/*
 * Curl_resolver_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 */
CURLcode Curl_resolver_is_resolved(struct connectdata *conn,
                                   struct Curl_dns_entry **entry)
{
  struct Curl_easy *data = conn->data;
  struct thread_data   *td = (struct thread_data*) conn->async.os_specific;
  int done = 0;

  *entry = NULL;

  if(!td) {
    DEBUGASSERT(td);
    return CURLE_COULDNT_RESOLVE_HOST;
  }

  Curl_mutex_acquire(td->tsd.mtx);
  done = td->tsd.done;
  Curl_mutex_release(td->tsd.mtx);

  if(done) {
    getaddrinfo_complete(conn);

    if(!conn->async.dns) {
      CURLcode result = resolver_error(conn);
      destroy_async_data(&conn->async);
      return result;
    }
    destroy_async_data(&conn->async);
    *entry = conn->async.dns;
  }
  else {
    /* poll for name lookup done with exponential backoff up to 250ms */
    /* should be fine even if this converts to 32 bit */
    time_t elapsed = (time_t)Curl_timediff(Curl_now(),
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
    Curl_expire(conn->data, td->poll_interval, EXPIRE_ASYNC_NAME);
  }

  return CURLE_OK;
}

int Curl_resolver_getsock(struct connectdata *conn,
                          curl_socket_t *socks)
{
  int ret_val = 0;
  time_t milli;
  timediff_t ms;
  struct Curl_easy *data = conn->data;
  struct resdata *reslv = (struct resdata *)data->state.resolver;
#ifdef USE_SOCKETPAIR
  struct thread_data *td = (struct thread_data*)conn->async.os_specific;
#else
  (void)socks;
#endif

#ifdef USE_SOCKETPAIR
  if(td) {
    /* return read fd to client for polling the DNS resolution status */
    socks[0] = td->tsd.sock_pair[0];
    DEBUGASSERT(td->tsd.conn == conn || !td->tsd.conn);
    td->tsd.conn = conn;
    ret_val = GETSOCK_READSOCK(0);
  }
  else {
#endif
    ms = Curl_timediff(Curl_now(), reslv->start);
    if(ms < 3)
      milli = 0;
    else if(ms <= 50)
      milli = (time_t)ms/3;
    else if(ms <= 250)
      milli = 50;
    else
      milli = 200;
    Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
#ifdef USE_SOCKETPAIR
  }
#endif


  return ret_val;
}

#ifndef HAVE_GETADDRINFO
/*
 * Curl_getaddrinfo() - for platforms without getaddrinfo
 */
Curl_addrinfo *Curl_resolver_getaddrinfo(struct connectdata *conn,
                                         const char *hostname,
                                         int port,
                                         int *waitp)
{
  struct Curl_easy *data = conn->data;
  struct resdata *reslv = (struct resdata *)data->state.resolver;

  *waitp = 0; /* default to synchronous response */

  reslv->start = Curl_now();

  /* fire up a new resolver thread! */
  if(init_resolve_thread(conn, hostname, port, NULL)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(conn->data, "getaddrinfo() thread failed\n");

  return NULL;
}

#else /* !HAVE_GETADDRINFO */

/*
 * Curl_resolver_getaddrinfo() - for getaddrinfo
 */
Curl_addrinfo *Curl_resolver_getaddrinfo(struct connectdata *conn,
                                         const char *hostname,
                                         int port,
                                         int *waitp)
{
  struct addrinfo hints;
  int pf = PF_INET;
  struct Curl_easy *data = conn->data;
  struct resdata *reslv = (struct resdata *)data->state.resolver;

  *waitp = 0; /* default to synchronous response */

#ifdef CURLRES_IPV6
  /*
   * Check if a limited name resolve has been requested.
   */
  switch(conn->ip_version) {
  case CURL_IPRESOLVE_V4:
    pf = PF_INET;
    break;
  case CURL_IPRESOLVE_V6:
    pf = PF_INET6;
    break;
  default:
    pf = PF_UNSPEC;
    break;
  }

  if((pf != PF_INET) && !Curl_ipv6works(conn))
    /* The stack seems to be a non-IPv6 one */
    pf = PF_INET;
#endif /* CURLRES_IPV6 */

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = (conn->transport == TRNSPRT_TCP)?
    SOCK_STREAM : SOCK_DGRAM;

  reslv->start = Curl_now();
  /* fire up a new resolver thread! */
  if(init_resolve_thread(conn, hostname, port, &hints)) {
    *waitp = 1; /* expect asynchronous response */
    return NULL;
  }

  failf(data, "getaddrinfo() thread failed to start\n");
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
