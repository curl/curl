/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_AGRES

#include <netdb.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_PTHREAD_H
# include <pthread.h>
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
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

struct resolver {
  struct {
    curl_mutex_t lock;
    int flag;
  } done;
  struct {
    struct sigevent event;
    struct addrinfo hint;
    struct gaicb cb_buf;
    struct gaicb *cb_ptr[1];
  } gai;
  struct {
    timediff_t expire;
    char *hostname;
    char service[12];
  } data;
};

#define AGRES_DEBUG 0
#define AGRES_EXPIRE_INIT 2U
#define AGRES_EXPIRE_GROW 2U
#define AGRES_EXPIRE_MAX (2U<<8)

static void set_done(struct resolver *res)
{
  DEBUGASSERT(res);
  if(res) {
    Curl_mutex_acquire(&res->done.lock);
    res->done.flag = 1;
    Curl_mutex_release(&res->done.lock);
  }
}

static int done(struct resolver *res)
{
  int done = 0;

  DEBUGASSERT(res);
  if(res) {
    Curl_mutex_acquire(&res->done.lock);
    done = res->done.flag;
    Curl_mutex_release(&res->done.lock);
  }
  return done;
}

static void notify(union sigval v)
{
  struct Curl_easy *data = v.sival_ptr;

  if(data)
    set_done(data->state.async.resolver);
}

/*
 * Curl_resolver_global_init()
 *
 * Called from curl_global_init() to initialize global resolver environment.
 * Returning anything else than CURLE_OK fails curl_global_init().
 */
int Curl_resolver_global_init(void)
{
  return CURLE_OK;
}

/*
 * Curl_resolver_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 */
void Curl_resolver_global_cleanup(void)
{
}

/*
 * Curl_resolver_init()
 * Called from curl_easy_init() -> Curl_open() to initialize resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).  Should fill the passed pointer by the initialized handler.
 * Returning anything else than CURLE_OK fails curl_easy_init() with the
 * correspondent code.
 */
CURLcode Curl_resolver_init(struct Curl_easy *data, void **resolver)
{
  struct resolver *res;

  *resolver = NULL;

  res = calloc(1, sizeof(struct resolver));
  if(!res)
    return CURLE_OUT_OF_MEMORY;

  Curl_mutex_init(&res->done.lock);
  res->gai.event.sigev_notify = SIGEV_THREAD;
  res->gai.event.sigev_notify_function = notify;
  res->gai.event.sigev_value.sival_ptr = data;
  res->gai.cb_buf.ar_request = &res->gai.hint;
  res->gai.cb_ptr[0] = &res->gai.cb_buf;

#if AGRES_DEBUG
  infof(data, "RESOLVER: init: %p\n", res);
#endif

  *resolver = res;
  return CURLE_OK;
}

/*
 * Curl_resolver_cleanup()
 * Called from curl_easy_cleanup() -> Curl_close() to cleanup resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure).  Should destroy the handler and free all resources connected to
 * it.
 */
void Curl_resolver_cleanup(void *resolver)
{
  struct resolver *res = resolver;

#if AGRES_DEBUG
  if(res && res->gai.event.sigev_value.sival_ptr)
    infof(res->gai.event.sigev_value.sival_ptr, "RESOLVER: cleanup: %p\n",
        res);
#endif

  if(!res)
    return;

  Curl_mutex_destroy(&res->done.lock);
  free(res->data.hostname);
  free(res);
}

/*
 * Curl_resolver_duphandle()
 * Called from curl_easy_duphandle() to duplicate resolver URL-state specific
 * environment ('resolver' member of the UrlState structure).  Should
 * duplicate the 'from' handle and pass the resulting handle to the 'to'
 * pointer.  Returning anything else than CURLE_OK causes failed
 * curl_easy_duphandle() call.
 */
CURLcode Curl_resolver_duphandle(struct Curl_easy *data, void **to,
                                 void *from)
{
  (void)from;
  return Curl_resolver_init(data, to);
}

/*
 * Curl_resolver_cancel().
 *
 * It is called from inside other functions to cancel currently performing
 * resolver request. Should also free any temporary resources allocated to
 * perform a request.  This never waits for resolver threads to complete.
 *
 * It is safe to call this when conn is in any state.
 */
void Curl_resolver_cancel(struct Curl_easy *data)
{
  struct resolver *resolver = data->state.async.resolver;

#if AGRES_DEBUG
  infof(data, "RESOLVER: cancel: %p\n", resolver);
#endif

  if(resolver) {
    int gai_rc = gai_cancel(resolver->gai.cb_ptr[0]);
    if(EAI_NOTCANCELED == gai_rc) {
      infof(data, "Could not cancel DNS request: %s\n",
          gai_strerror(gai_rc));
    }

    resolver->gai.event.sigev_value.sival_ptr = NULL;
  }
}

/*
 * Curl_resolver_kill().
 *
 * This acts like Curl_resolver_cancel() except it will block until any threads
 * associated with the resolver are complete.  This never blocks for resolvers
 * that do not use threads.  This is intended to be the "last chance" function
 * that cleans up an in-progress resolver completely (before its owner is about
 * to die).
 *
 * It is safe to call this when conn is in any state.
 */
void Curl_resolver_kill(struct Curl_easy *data)
{
#if AGRES_DEBUG
  infof(data, "RESOLVER: kill: %p\n", data->state.async.resolver);
#endif
  Curl_resolver_cancel(data);
}

/* Curl_resolver_getsock()
 *
 * This function is called from the multi_getsock() function.  'sock' is a
 * pointer to an array to hold the file descriptors, with 'numsock' being the
 * size of that array (in number of entries). This function is supposed to
 * return bitmask indicating what file descriptors (referring to array indexes
 * in the 'sock' array) to wait for, read/write.
 */
int Curl_resolver_getsock(struct Curl_easy *data, curl_socket_t *sock)
{
  struct resolver *resolver = data->state.async.resolver;

  (void)sock;

#if AGRES_DEBUG
    infof(data, "RESOLVER: getsock: %p expire %d\n",
        resolver, resolver->data.expire);
#endif

  Curl_expire(data, resolver->data.expire, EXPIRE_ASYNC_NAME);
  return 0;
}

/*
 * Curl_resolver_is_resolved()
 *
 * Called repeatedly to check if a previous name resolve request has
 * completed. It should also make sure to time-out if the operation seems to
 * take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_resolver_is_resolved(struct Curl_easy *data,
                                   struct Curl_dns_entry **dns)
{
  struct resolver *resolver = data->state.async.resolver;
  timediff_t left;

#if AGRES_DEBUG
  infof(data, "RESOLVER: is_resolved: %p\n", resolver);
#endif

  if(!resolver)
    return Curl_resolver_error(data);

  if(done(resolver)) {
    struct Curl_addrinfo *ca = NULL;
    CURLcode rc1 = Curl_ai2ca(resolver->gai.cb_buf.ar_result, &ca);
    CURLcode rc2 = Curl_addrinfo_callback(data, rc1, ca);

#if AGRES_DEBUG
    infof(data, "RESOLVER: is_resolved: %p done (%d)\n",
        resolver, rc1|rc2);
#endif

    if(CURLE_OK != rc1 || CURLE_OK != rc2)
      return Curl_resolver_error(data);

    *dns = data->state.async.dns;
    if(!*dns)
      return Curl_resolver_error(data);

    return CURLE_OK;
  }

  /* time out if no more time is left for us */
  left = Curl_timeleft(data, NULL, 1);
  if(left < 0) {
#if AGRES_DEBUG
    infof(data, "RESOLVER: is_resolved: %p timeout\n", resolver);
#endif

    Curl_resolver_cancel(data);
    Curl_addrinfo_callback(data, CURLE_OPERATION_TIMEDOUT, NULL);
    return CURLE_OPERATION_TIMEDOUT;
  }

  /* initialize expire ms for get_sock() and back off for repeated calls */
  if(resolver->data.expire == 0)
    resolver->data.expire = AGRES_EXPIRE_INIT;
  else
    resolver->data.expire *= AGRES_EXPIRE_GROW;
  if(resolver->data.expire > left)
    resolver->data.expire = left;
  if(resolver->data.expire > AGRES_EXPIRE_MAX)
    resolver->data.expire = AGRES_EXPIRE_MAX;

  return CURLE_OK;
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
 */
CURLcode Curl_resolver_wait_resolv(struct Curl_easy *data,
                                   struct Curl_dns_entry **dnsentry)
{
  struct Curl_dns_entry *dns = NULL;
  CURLcode rc;

#if AGRES_DEBUG
  infof(data, "RESOLVER: wait: %p\n", data->state.async.resolver);
#endif

  do {
    rc = Curl_resolver_is_resolved(data, &dns);
  } while(CURLE_OK == rc && !dns);

  if(dnsentry)
    *dnsentry = dns;

  return rc;
}

/*
 * Curl_resolver_getaddrinfo() - when using this resolver
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the forth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 *
 * Each resolver backend must of course make sure to return data in the
 * correct format to comply with this.
 */
struct Curl_addrinfo *Curl_resolver_getaddrinfo(struct Curl_easy *data,
                                                const char *hostname,
                                                int port,
                                                int *waitp)
{
  int gai_rc, pf = PF_INET;
  struct Curl_async *async = &data->state.async;
  struct resolver *resolver = async->resolver;
  const char *error;

  *waitp = 0; /* default to synchronous response */

  async->port = 0;
  async->done = FALSE;
  async->status = 0;
  async->hostname = NULL;

#ifdef CURLRES_IPV6
  /*
   * Check if a limited name resolve has been requested.
   */
  switch(data->set.ipver) {
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

  if((pf != PF_INET) && !Curl_ipv6works(data))
    /* The stack seems to be a non-IPv6 one */
    pf = PF_INET;
#endif /* CURLRES_IPV6 */

#if AGRES_DEBUG
  infof(data, "RESOLVER: getaddrinfo: %p (%s:%d)\n",
      resolver, hostname, port);
#endif

  memset(&resolver->gai.hint, 0, sizeof(resolver->gai.hint));
  resolver->gai.hint.ai_family = pf;
  resolver->gai.hint.ai_socktype = (data->conn->transport == TRNSPRT_TCP)?
    SOCK_STREAM : SOCK_DGRAM;

  free(resolver->data.hostname);
  resolver->data.hostname = strdup(hostname);
  if(!resolver->data.hostname) {
    error = "out of memory";
    goto fail;
  }
  msnprintf(
      resolver->data.service, sizeof(resolver->data.service), "%d", port);
  resolver->gai.cb_buf.ar_service = &resolver->data.service[0];
  resolver->gai.cb_buf.ar_name = resolver->data.hostname;

  async->port = port;
  async->hostname = resolver->data.hostname;

  gai_rc = getaddrinfo_a(
      GAI_NOWAIT, resolver->gai.cb_ptr, 1, &resolver->gai.event);
  if(gai_rc) {
    error = gai_strerror(gai_rc);
    goto fail;
  }

  *waitp = 1;
  return NULL;

fail:
  failf(data, "getaddrinfo() failed to initialize: %s", error);
  return NULL;
}

/* missing from header: */

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

#endif
