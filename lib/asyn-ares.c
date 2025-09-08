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

#ifdef CURLRES_ARES

/***********************************************************************
 * Only for ares-enabled builds
 * And only for functions that fulfill the asynch resolver backend API
 * as defined in asyn.h, nothing else belongs in this file!
 **********************************************************************/

#include <limits.h>
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

#include "urldata.h"
#include "cfilters.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "multiif.h"
#include "curlx/inet_pton.h"
#include "connect.h"
#include "select.h"
#include "progress.h"
#include "curlx/timediff.h"
#include "httpsrr.h"
#include "strdup.h"

#include <ares.h>
#include <ares_version.h> /* really old c-ares did not include this by
                             itself */

#if ARES_VERSION >= 0x010601
/* IPv6 supported since 1.6.1 */
#define HAVE_CARES_IPV6 1
#endif

#if ARES_VERSION >= 0x010704
#define HAVE_CARES_SERVERS_CSV 1
#define HAVE_CARES_LOCAL_DEV 1
#define HAVE_CARES_SET_LOCAL 1
#endif

#if ARES_VERSION >= 0x010b00
#define HAVE_CARES_PORTS_CSV 1
#endif

#if ARES_VERSION >= 0x011000
/* 1.16.0 or later has ares_getaddrinfo */
#define HAVE_CARES_GETADDRINFO 1
#endif

#ifdef USE_HTTPSRR
#if ARES_VERSION < 0x011c00
#error "requires c-ares 1.28.0 or newer for HTTPSRR"
#endif
#define HTTPSRR_WORKS
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* How long we are willing to wait for additional parallel responses after
   obtaining a "definitive" one. For old c-ares without getaddrinfo.

   This is intended to equal the c-ares default timeout. cURL always uses that
   default value. Unfortunately, c-ares does not expose its default timeout in
   its API, but it is officially documented as 5 seconds.

   See query_completed_cb() for an explanation of how this is used.
 */
#define HAPPY_EYEBALLS_DNS_TIMEOUT 5000

#define CARES_TIMEOUT_PER_ATTEMPT 2000

static int ares_ver = 0;

static CURLcode async_ares_set_dns_servers(struct Curl_easy *data,
                                           bool reset_on_null);

/*
 * Curl_async_global_init() - the generic low-level asynchronous name
 * resolve API. Called from curl_global_init() to initialize global resolver
 * environment. Initializes ares library.
 */
int Curl_async_global_init(void)
{
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
  if(ares_library_init(ARES_LIB_INIT_ALL)) {
    return CURLE_FAILED_INIT;
  }
#endif
  ares_version(&ares_ver);
  return CURLE_OK;
}

/*
 * Curl_async_global_cleanup()
 *
 * Called from curl_global_cleanup() to destroy global resolver environment.
 * Deinitializes ares library.
 */
void Curl_async_global_cleanup(void)
{
#ifdef CARES_HAVE_ARES_LIBRARY_CLEANUP
  ares_library_cleanup();
#endif
}


static void sock_state_cb(void *data, ares_socket_t socket_fd,
                          int readable, int writable)
{
  struct Curl_easy *easy = data;
  if(!readable && !writable) {
    DEBUGASSERT(easy);
    Curl_multi_will_close(easy, socket_fd);
  }
}

static CURLcode async_ares_init(struct Curl_easy *data)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  int status;
  struct ares_options options;
  int optmask = ARES_OPT_SOCK_STATE_CB;
  CURLcode rc = CURLE_OK;

  options.sock_state_cb = sock_state_cb;
  options.sock_state_cb_data = data;

  DEBUGASSERT(!ares->channel);
  /*
     if c ares < 1.20.0: curl set timeout to CARES_TIMEOUT_PER_ATTEMPT (2s)

     if c-ares >= 1.20.0 it already has the timeout to 2s, curl does not need
     to set the timeout value;

     if c-ares >= 1.24.0, user can set the timeout via /etc/resolv.conf to
     overwrite c-ares' timeout.
  */
  DEBUGASSERT(ares_ver);
  if(ares_ver < 0x011400) {
    options.timeout = CARES_TIMEOUT_PER_ATTEMPT;
    optmask |= ARES_OPT_TIMEOUTMS;
  }

  status = ares_init_options(&ares->channel, &options, optmask);
  if(status != ARES_SUCCESS) {
    ares->channel = NULL;
    rc = (status == ARES_ENOMEM) ?
         CURLE_OUT_OF_MEMORY : CURLE_FAILED_INIT;
    goto out;
  }

  rc = async_ares_set_dns_servers(data, FALSE);
  if(rc && rc != CURLE_NOT_BUILT_IN)
    goto out;

  rc = Curl_async_ares_set_dns_interface(data);
  if(rc && rc != CURLE_NOT_BUILT_IN)
    goto out;

  rc = Curl_async_ares_set_dns_local_ip4(data);
  if(rc && rc != CURLE_NOT_BUILT_IN)
    goto out;

  rc = Curl_async_ares_set_dns_local_ip6(data);
  if(rc && rc != CURLE_NOT_BUILT_IN)
    goto out;

  rc = CURLE_OK;

out:
  if(rc && ares->channel) {
    ares_destroy(ares->channel);
    ares->channel = NULL;
  }
  return rc;
}

static CURLcode async_ares_init_lazy(struct Curl_easy *data)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  if(!ares->channel)
    return async_ares_init(data);
  return CURLE_OK;
}

CURLcode Curl_async_get_impl(struct Curl_easy *data, void **impl)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  CURLcode result = CURLE_OK;
  if(!ares->channel) {
    result = async_ares_init(data);
  }
  *impl = ares->channel;
  return result;
}

/*
 * async_ares_cleanup() cleans up async resolver data.
 */
static void async_ares_cleanup(struct Curl_easy *data)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  if(ares->temp_ai) {
    Curl_freeaddrinfo(ares->temp_ai);
    ares->temp_ai = NULL;
  }
#ifdef USE_HTTPSRR
  Curl_httpsrr_cleanup(&ares->hinfo);
#endif
}

void Curl_async_ares_shutdown(struct Curl_easy *data)
{
  /* c-ares has a method to "cancel" operations on a channel, but
   * as reported in #18216, this does not totally reset the channel
   * and ares may get stuck.
   * We need to destroy the channel and on demand create a new
   * one to avoid that. */
  Curl_async_ares_destroy(data);
}

void Curl_async_ares_destroy(struct Curl_easy *data)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  if(ares->channel) {
    ares_destroy(ares->channel);
    ares->channel = NULL;
  }
  async_ares_cleanup(data);
}

/*
 * Curl_async_pollset() is called when someone from the outside world
 * (using curl_multi_fdset()) wants to get our fd_set setup.
 */

CURLcode Curl_async_pollset(struct Curl_easy *data, struct easy_pollset *ps)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  if(ares->channel)
    return Curl_ares_pollset(data, ares->channel, ps);
  return CURLE_OK;
}

/*
 * Curl_async_is_resolved() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_async_is_resolved(struct Curl_easy *data,
                                struct Curl_dns_entry **dns)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(dns);
  *dns = NULL;

  if(data->state.async.done) {
    *dns = data->state.async.dns;
    return CURLE_OK;
  }

  if(Curl_ares_perform(ares->channel, 0) < 0)
    return CURLE_UNRECOVERABLE_POLL;

#ifndef HAVE_CARES_GETADDRINFO
  /* Now that we have checked for any last minute results above, see if there
     are any responses still pending when the EXPIRE_HAPPY_EYEBALLS_DNS timer
     expires. */
  if(ares->num_pending
     /* This is only set to non-zero if the timer was started. */
     && (ares->happy_eyeballs_dns_time.tv_sec
         || ares->happy_eyeballs_dns_time.tv_usec)
     && (curlx_timediff(curlx_now(), ares->happy_eyeballs_dns_time)
         >= HAPPY_EYEBALLS_DNS_TIMEOUT)) {
    /* Remember that the EXPIRE_HAPPY_EYEBALLS_DNS timer is no longer
       running. */
    memset(&ares->happy_eyeballs_dns_time, 0,
           sizeof(ares->happy_eyeballs_dns_time));

    /* Cancel the raw c-ares request, which will fire query_completed_cb() with
       ARES_ECANCELLED synchronously for all pending responses. This will
       leave us with res->num_pending == 0, which is perfect for the next
       block. */
    ares_cancel(ares->channel);
    DEBUGASSERT(ares->num_pending == 0);
  }
#endif

  if(!ares->num_pending) {
    /* all c-ares operations done, what is the result to report? */
    Curl_resolv_unlink(data, &data->state.async.dns);
    data->state.async.done = TRUE;
    result = ares->result;
    if(ares->ares_status == ARES_SUCCESS && !result) {
      data->state.async.dns =
        Curl_dnscache_mk_entry(data, ares->temp_ai,
                               data->state.async.hostname, 0,
                               data->state.async.port, FALSE);
      ares->temp_ai = NULL; /* temp_ai now owned by entry */
#ifdef HTTPSRR_WORKS
      if(data->state.async.dns) {
        struct Curl_https_rrinfo *lhrr = Curl_httpsrr_dup_move(&ares->hinfo);
        if(!lhrr)
          result = CURLE_OUT_OF_MEMORY;
        else
          data->state.async.dns->hinfo = lhrr;
      }
#endif
      if(!result && data->state.async.dns)
        result = Curl_dnscache_add(data, data->state.async.dns);
    }
    /* if we have not found anything, report the proper
     * CURLE_COULDNT_RESOLVE_* code */
    if(!result && !data->state.async.dns) {
      const char *msg = NULL;
      if(ares->ares_status != ARES_SUCCESS)
        msg = ares_strerror(ares->ares_status);
      result = Curl_resolver_error(data, msg);
    }

    if(result)
      Curl_resolv_unlink(data, &data->state.async.dns);
    *dns = data->state.async.dns;
    CURL_TRC_DNS(data, "is_resolved() result=%d, dns=%sfound",
                 result, *dns ? "" : "not ");
    async_ares_cleanup(data);
  }
  return result;
}

/*
 * Curl_async_await()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * 'entry' MUST be non-NULL.
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 */
CURLcode Curl_async_await(struct Curl_easy *data,
                          struct Curl_dns_entry **entry)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  CURLcode result = CURLE_OK;
  timediff_t timeout;
  struct curltime now = curlx_now();

  DEBUGASSERT(entry);
  *entry = NULL; /* clear on entry */

  timeout = Curl_timeleft(data, &now, TRUE);
  if(timeout < 0) {
    /* already expired! */
    connclose(data->conn, "Timed out before name resolve started");
    return CURLE_OPERATION_TIMEDOUT;
  }
  if(!timeout)
    timeout = CURL_TIMEOUT_RESOLVE * 1000; /* default name resolve timeout */

  /* Wait for the name resolve query to complete. */
  while(!result) {
    struct timeval *tvp, tv, store;
    int itimeout;
    timediff_t timeout_ms;

#if TIMEDIFF_T_MAX > INT_MAX
    itimeout = (timeout > INT_MAX) ? INT_MAX : (int)timeout;
#else
    itimeout = (int)timeout;
#endif

    store.tv_sec = itimeout/1000;
    store.tv_usec = (itimeout%1000)*1000;

    tvp = ares_timeout(ares->channel, &store, &tv);

    /* use the timeout period ares returned to us above if less than one
       second is left, otherwise just use 1000ms to make sure the progress
       callback gets called frequent enough */
    if(!tvp->tv_sec)
      timeout_ms = (timediff_t)(tvp->tv_usec/1000);
    else
      timeout_ms = 1000;

    if(Curl_ares_perform(ares->channel, timeout_ms) < 0)
      return CURLE_UNRECOVERABLE_POLL;

    result = Curl_async_is_resolved(data, entry);
    if(result || data->state.async.done)
      break;

    if(Curl_pgrsUpdate(data))
      result = CURLE_ABORTED_BY_CALLBACK;
    else {
      struct curltime now2 = curlx_now();
      timediff_t timediff = curlx_timediff(now2, now); /* spent time */
      if(timediff <= 0)
        timeout -= 1; /* always deduct at least 1 */
      else if(timediff > timeout)
        timeout = -1;
      else
        timeout -= timediff;
      now = now2; /* for next loop */
    }
    if(timeout < 0)
      result = CURLE_OPERATION_TIMEDOUT;
  }

  /* Operation complete, if the lookup was successful we now have the entry
     in the cache. */
  data->state.async.done = TRUE;
  *entry = data->state.async.dns;

  if(result)
    ares_cancel(ares->channel);
  return result;
}

#ifndef HAVE_CARES_GETADDRINFO

/* Connects results to the list */
static void async_addr_concat(struct Curl_addrinfo **pbase,
                              struct Curl_addrinfo *ai)
{
  if(!ai)
    return;

  /* When adding `ai` to an existing address list, we prefer ipv6
   * to be in front. */
#ifdef USE_IPV6 /* CURLRES_IPV6 */
  if(*pbase && (*pbase)->ai_family == PF_INET6) {
    /* ipv6 already in front, append `ai` */
    struct Curl_addrinfo *tail = *pbase;
    while(tail->ai_next)
      tail = tail->ai_next;
    tail->ai_next = ai;
  }
  else
#endif /* CURLRES_IPV6 */
  {
    /* prepend to the (possibly) existing list. */
    struct Curl_addrinfo *tail = ai;
    while(tail->ai_next)
      tail = tail->ai_next;
    tail->ai_next = *pbase;
    *pbase = ai;
  }
}

/*
 * ares_query_completed_cb() is the callback that ares will call when
 * the host query initiated by ares_gethostbyname() from
 * Curl_async_getaddrinfo(), when using ares, is completed either
 * successfully or with failure.
 */
static void async_ares_hostbyname_cb(void *user_data,
                                     int status,
                                     int timeouts,
                                     struct hostent *hostent)
{
  struct Curl_easy *data = (struct Curl_easy *)user_data;
  struct async_ares_ctx *ares = &data->state.async.ares;

  (void)timeouts; /* ignored */

  if(ARES_EDESTRUCTION == status)
    /* when this ares handle is getting destroyed, the 'arg' pointer may not
       be valid so only defer it when we know the 'status' says its fine! */
    return;

  if(ARES_SUCCESS == status) {
    ares->ares_status = status; /* one success overrules any error */
    async_addr_concat(&ares->temp_ai,
      Curl_he2ai(hostent, data->state.async.port));
  }
  else if(ares->ares_status != ARES_SUCCESS) {
    /* no success so far, remember last error */
    ares->ares_status = status;
  }

  ares->num_pending--;

  CURL_TRC_DNS(data, "ares: hostbyname done, status=%d, pending=%d, "
               "addr=%sfound",
               status, ares->num_pending, ares->temp_ai ? "" : "not ");
  /* If there are responses still pending, we presume they must be the
     complementary IPv4 or IPv6 lookups that we started in parallel in
     Curl_async_getaddrinfo() (for Happy Eyeballs). If we have got a
     "definitive" response from one of a set of parallel queries, we need to
     think about how long we are willing to wait for more responses. */
  if(ares->num_pending
     /* Only these c-ares status values count as "definitive" for these
        purposes. For example, ARES_ENODATA is what we expect when there is
        no IPv6 entry for a domain name, and that is not a reason to get more
        aggressive in our timeouts for the other response. Other errors are
        either a result of bad input (which should affect all parallel
        requests), local or network conditions, non-definitive server
        responses, or us cancelling the request. */
     && (status == ARES_SUCCESS || status == ARES_ENOTFOUND)) {
    /* Right now, there can only be up to two parallel queries, so do not
       bother handling any other cases. */
    DEBUGASSERT(ares->num_pending == 1);

    /* it is possible that one of these parallel queries could succeed
       quickly, but the other could always fail or timeout (when we are
       talking to a pool of DNS servers that can only successfully resolve
       IPv4 address, for example).

       it is also possible that the other request could always just take
       longer because it needs more time or only the second DNS server can
       fulfill it successfully. But, to align with the philosophy of Happy
       Eyeballs, we do not want to wait _too_ long or users will think
       requests are slow when IPv6 lookups do not actually work (but IPv4
       ones do).

       So, now that we have a usable answer (some IPv4 addresses, some IPv6
       addresses, or "no such domain"), we start a timeout for the remaining
       pending responses. Even though it is typical that this resolved
       request came back quickly, that needn't be the case. It might be that
       this completing request did not get a result from the first DNS
       server or even the first round of the whole DNS server pool. So it
       could already be quite some time after we issued the DNS queries in
       the first place. Without modifying c-ares, we cannot know exactly
       where in its retry cycle we are. We could guess based on how much
       time has gone by, but it does not really matter. Happy Eyeballs tells
       us that, given usable information in hand, we simply do not want to
       wait "too much longer" after we get a result.

       We simply wait an additional amount of time equal to the default
       c-ares query timeout. That is enough time for a typical parallel
       response to arrive without being "too long". Even on a network
       where one of the two types of queries is failing or timing out
       constantly, this will usually mean we wait a total of the default
       c-ares timeout (5 seconds) plus the round trip time for the successful
       request, which seems bearable. The downside is that c-ares might race
       with us to issue one more retry just before we give up, but it seems
       better to "waste" that request instead of trying to guess the perfect
       timeout to prevent it. After all, we do not even know where in the
       c-ares retry cycle each request is.
    */
    ares->happy_eyeballs_dns_time = curlx_now();
    Curl_expire(data, HAPPY_EYEBALLS_DNS_TIMEOUT,
                EXPIRE_HAPPY_EYEBALLS_DNS);
  }
}

#else
/* c-ares 1.16.0 or later */

/*
 * async_ares_node2addr() converts an address list provided by c-ares
 * to an internal libcurl compatible list.
 */
static struct Curl_addrinfo *
async_ares_node2addr(struct ares_addrinfo_node *node)
{
  /* traverse the ares_addrinfo_node list */
  struct ares_addrinfo_node *ai;
  struct Curl_addrinfo *cafirst = NULL;
  struct Curl_addrinfo *calast = NULL;
  int error = 0;

  for(ai = node; ai != NULL; ai = ai->ai_next) {
    size_t ss_size;
    struct Curl_addrinfo *ca;
    /* ignore elements with unsupported address family, */
    /* settle family-specific sockaddr structure size.  */
    if(ai->ai_family == AF_INET)
      ss_size = sizeof(struct sockaddr_in);
#ifdef USE_IPV6
    else if(ai->ai_family == AF_INET6)
      ss_size = sizeof(struct sockaddr_in6);
#endif
    else
      continue;

    /* ignore elements without required address info */
    if(!ai->ai_addr || !(ai->ai_addrlen > 0))
      continue;

    /* ignore elements with bogus address size */
    if((size_t)ai->ai_addrlen < ss_size)
      continue;

    ca = malloc(sizeof(struct Curl_addrinfo) + ss_size);
    if(!ca) {
      error = EAI_MEMORY;
      break;
    }

    /* copy each structure member individually, member ordering, */
    /* size, or padding might be different for each platform.    */

    ca->ai_flags     = ai->ai_flags;
    ca->ai_family    = ai->ai_family;
    ca->ai_socktype  = ai->ai_socktype;
    ca->ai_protocol  = ai->ai_protocol;
    ca->ai_addrlen   = (curl_socklen_t)ss_size;
    ca->ai_addr      = NULL;
    ca->ai_canonname = NULL;
    ca->ai_next      = NULL;

    ca->ai_addr = (void *)((char *)ca + sizeof(struct Curl_addrinfo));
    memcpy(ca->ai_addr, ai->ai_addr, ss_size);

    /* if the return list is empty, this becomes the first element */
    if(!cafirst)
      cafirst = ca;

    /* add this element last in the return list */
    if(calast)
      calast->ai_next = ca;
    calast = ca;
  }

  /* if we failed, destroy the Curl_addrinfo list */
  if(error) {
    Curl_freeaddrinfo(cafirst);
    cafirst = NULL;
  }

  return cafirst;
}

static void async_ares_addrinfo_cb(void *user_data, int status, int timeouts,
                                   struct ares_addrinfo *ares_ai)
{
  struct Curl_easy *data = (struct Curl_easy *)user_data;
  struct async_ares_ctx *ares = &data->state.async.ares;
  (void)timeouts;
  if(ares->ares_status != ARES_SUCCESS) /* do not overwrite success */
    ares->ares_status = status;
  if(status == ARES_SUCCESS) {
    ares->temp_ai = async_ares_node2addr(ares_ai->nodes);
    ares_freeaddrinfo(ares_ai);
  }
  ares->num_pending--;
  CURL_TRC_DNS(data, "ares: addrinfo done, query status=%d, "
               "overall status=%d, pending=%d, addr=%sfound",
               status, ares->ares_status, ares->num_pending,
               ares->temp_ai ? "" : "not ");
}

#endif

#ifdef USE_HTTPSRR
static void async_ares_rr_done(void *user_data, ares_status_t status,
                               size_t timeouts,
                               const ares_dns_record_t *dnsrec)
{
  struct Curl_easy *data = user_data;
  struct async_ares_ctx *ares = &data->state.async.ares;

  (void)timeouts;
  --ares->num_pending;
  CURL_TRC_DNS(data, "ares: httpsrr done, status=%d, pending=%d, "
               "dnsres=%sfound",
               status, ares->num_pending,
               (dnsrec &&
                ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER)) ?
                "" : "not ");
  if((ARES_SUCCESS != status) || !dnsrec)
    return;
  ares->result = Curl_httpsrr_from_ares(data, dnsrec, &ares->hinfo);
}
#endif /* USE_HTTPSRR */

/*
 * Curl_async_getaddrinfo() - when using ares
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the fourth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
struct Curl_addrinfo *Curl_async_getaddrinfo(struct Curl_easy *data,
                                             const char *hostname,
                                             int port,
                                             int ip_version,
                                             int *waitp)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  *waitp = 0; /* default to synchronous response */

  if(async_ares_init_lazy(data))
    return NULL;

  data->state.async.done = FALSE;   /* not done */
  data->state.async.dns = NULL;     /* clear */
  data->state.async.port = port;
  data->state.async.ip_version = ip_version;
  data->state.async.hostname = strdup(hostname);
  if(!data->state.async.hostname)
    return NULL;

  /* initial status - failed */
  ares->ares_status = ARES_ENOTFOUND;
  ares->result = CURLE_OK;

#if ARES_VERSION >= 0x011800  /* >= v1.24.0 */
  CURL_TRC_DNS(data, "asyn-ares: servers=%s",
               ares_get_servers_csv(ares->channel));
#endif

#ifdef HAVE_CARES_GETADDRINFO
  {
    struct ares_addrinfo_hints hints;
    char service[12];
    int pf = PF_INET;
    memset(&hints, 0, sizeof(hints));
#ifdef CURLRES_IPV6
    if((ip_version != CURL_IPRESOLVE_V4) &&
       Curl_ipv6works(data)) {
      /* The stack seems to be IPv6-enabled */
      if(ip_version == CURL_IPRESOLVE_V6)
        pf = PF_INET6;
      else
        pf = PF_UNSPEC;
    }
#endif /* CURLRES_IPV6 */
    CURL_TRC_DNS(data, "asyn-ares: fire off getaddrinfo for %s",
                 (pf == PF_UNSPEC) ? "A+AAAA" :
                 ((pf == PF_INET) ? "A" : "AAAA"));
    hints.ai_family = pf;
    hints.ai_socktype =
      (Curl_conn_get_transport(data, data->conn) == TRNSPRT_TCP) ?
      SOCK_STREAM : SOCK_DGRAM;
    /* Since the service is a numerical one, set the hint flags
     * accordingly to save a call to getservbyname in inside C-Ares
     */
    hints.ai_flags = ARES_AI_NUMERICSERV;
    msnprintf(service, sizeof(service), "%d", port);
    ares->num_pending = 1;
    ares_getaddrinfo(ares->channel, data->state.async.hostname,
                     service, &hints, async_ares_addrinfo_cb, data);
  }
#else

#ifdef HAVE_CARES_IPV6
  if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
    /* The stack seems to be IPv6-enabled */
    /* areschannel is already setup in the Curl_open() function */
    CURL_TRC_DNS(data, "asyn-ares: fire off query for A");
    ares_gethostbyname(ares->channel, hostname, PF_INET,
                       async_ares_hostbyname_cb, data);
    CURL_TRC_DNS(data, "asyn-ares: fire off query for AAAA");
    ares->num_pending = 2;
    ares_gethostbyname(ares->channel, data->state.async.hostname, PF_INET6,
                       async_ares_hostbyname_cb, data);
  }
  else
#endif
  {
    /* areschannel is already setup in the Curl_open() function */
    CURL_TRC_DNS(data, "asyn-ares: fire off query for A");
    ares->num_pending = 1;
    ares_gethostbyname(ares->channel, data->state.async.hostname, PF_INET,
                       async_ares_hostbyname_cb, data);
  }
#endif
#ifdef USE_HTTPSRR
  {
    CURL_TRC_DNS(data, "asyn-ares: fire off query for HTTPSRR");
    memset(&ares->hinfo, 0, sizeof(ares->hinfo));
    ares->hinfo.port = -1;
    ares->num_pending++; /* one more */
    ares_query_dnsrec(ares->channel, data->state.async.hostname,
                      ARES_CLASS_IN, ARES_REC_TYPE_HTTPS,
                      async_ares_rr_done, data, NULL);
  }
#endif
  *waitp = 1; /* expect asynchronous response */

  return NULL; /* no struct yet */
}

/* Set what DNS server are is to use. This is called in 2 situations:
 * 1. when the application does 'CURLOPT_DNS_SERVERS' and passing NULL
 *    means any previous set value should be unset. Which means
 *    we need to destroy and create the are channel anew, if there is one.
 * 2. When we lazy init the ares channel and NULL means that there
 *    are no preferences and we do not reset any existing channel. */
static CURLcode async_ares_set_dns_servers(struct Curl_easy *data,
                                           bool reset_on_null)
{
  struct async_ares_ctx *ares = &data->state.async.ares;
  CURLcode result = CURLE_NOT_BUILT_IN;
  const char *servers = data->set.str[STRING_DNS_SERVERS];
  int ares_result = ARES_SUCCESS;

#if defined(CURLDEBUG) && defined(HAVE_CARES_SERVERS_CSV)
  if(getenv("CURL_DNS_SERVER"))
    servers = getenv("CURL_DNS_SERVER");
#endif

  if(!servers) {
    if(reset_on_null) {
      Curl_async_destroy(data);
    }
    return CURLE_OK;
  }

#ifdef HAVE_CARES_SERVERS_CSV
  /* if channel is not there, this is just a parameter check */
  if(ares->channel)
#ifdef HAVE_CARES_PORTS_CSV
    ares_result = ares_set_servers_ports_csv(ares->channel, servers);
#else
    ares_result = ares_set_servers_csv(ares->channel, servers);
#endif
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
    DEBUGF(infof(data, "bad servers set"));
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }
#else /* too old c-ares version! */
  (void)data;
  (void)(ares_result);
#endif
  return result;
}

CURLcode Curl_async_ares_set_dns_servers(struct Curl_easy *data)
{
  return async_ares_set_dns_servers(data, TRUE);
}

CURLcode Curl_async_ares_set_dns_interface(struct Curl_easy *data)
{
#ifdef HAVE_CARES_LOCAL_DEV
  struct async_ares_ctx *ares = &data->state.async.ares;
  const char *interf = data->set.str[STRING_DNS_INTERFACE];

  if(!interf)
    interf = "";

  /* if channel is not there, this is just a parameter check */
  if(ares->channel)
    ares_set_local_dev(ares->channel, interf);

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  (void)interf;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_async_ares_set_dns_local_ip4(struct Curl_easy *data)
{
#ifdef HAVE_CARES_SET_LOCAL
  struct async_ares_ctx *ares = &data->state.async.ares;
  struct in_addr a4;
  const char *local_ip4 = data->set.str[STRING_DNS_LOCAL_IP4];

  if((!local_ip4) || (local_ip4[0] == 0)) {
    a4.s_addr = 0; /* disabled: do not bind to a specific address */
  }
  else {
    if(curlx_inet_pton(AF_INET, local_ip4, &a4) != 1) {
      DEBUGF(infof(data, "bad DNS IPv4 address"));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  /* if channel is not there yet, this is just a parameter check */
  if(ares->channel)
    ares_set_local_ip4(ares->channel, ntohl(a4.s_addr));

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  (void)local_ip4;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_async_ares_set_dns_local_ip6(struct Curl_easy *data)
{
#if defined(HAVE_CARES_SET_LOCAL) && defined(USE_IPV6)
  struct async_ares_ctx *ares = &data->state.async.ares;
  unsigned char a6[INET6_ADDRSTRLEN];
  const char *local_ip6 = data->set.str[STRING_DNS_LOCAL_IP6];

  if((!local_ip6) || (local_ip6[0] == 0)) {
    /* disabled: do not bind to a specific address */
    memset(a6, 0, sizeof(a6));
  }
  else {
    if(curlx_inet_pton(AF_INET6, local_ip6, a6) != 1) {
      DEBUGF(infof(data, "bad DNS IPv6 address"));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  /* if channel is not there, this is just a parameter check */
  if(ares->channel)
    ares_set_local_ip6(ares->channel, a6);

  return CURLE_OK;
#else /* c-ares version too old! */
  (void)data;
  return CURLE_NOT_BUILT_IN;
#endif
}

#endif /* CURLRES_ARES */
