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

#ifdef USE_RESOLV_ARES

/***********************************************************************
 * Only for ares-enabled builds and only for functions that fulfill
 * the asynch resolver backend API as defined in asyn.h,
 * nothing else belongs in this file!
 **********************************************************************/

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
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "hostip.h"
#include "url.h"
#include "multiif.h"
#include "curlx/inet_pton.h"
#include "connect.h"
#include "select.h"
#include "progress.h"
#include "curlx/timediff.h"
#include "httpsrr.h"
#include <ares.h>

#if ARES_VERSION < 0x011000
#error "requires c-ares 1.16.0 or newer"
#endif

#ifdef USE_HTTPSRR
#if ARES_VERSION < 0x011c00
#error "requires c-ares 1.28.0 or newer for HTTPSRR"
#endif
#define HTTPSRR_WORKS
#endif

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

static CURLcode async_ares_init(struct Curl_easy *data,
                                struct Curl_resolv_async *async)
{
  struct async_ares_ctx *ares = &async->ares;
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
    rc = (status == ARES_ENOMEM) ? CURLE_OUT_OF_MEMORY : CURLE_FAILED_INIT;
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

static CURLcode async_ares_init_lazy(struct Curl_easy *data,
                                     struct Curl_resolv_async *async)
{
  struct async_ares_ctx *ares = &async->ares;
  if(!ares->channel)
    return async_ares_init(data, async);
  return CURLE_OK;
}

CURLcode Curl_async_get_impl(struct Curl_easy *data,
                             struct Curl_resolv_async *async,
                             void **impl)
{
  struct async_ares_ctx *ares = &async->ares;
  CURLcode result = CURLE_OK;
  if(!ares->channel) {
    result = async_ares_init(data, async);
  }
  *impl = ares->channel;
  return result;
}

/*
 * async_ares_cleanup() cleans up async resolver data.
 */
static void async_ares_cleanup(struct Curl_resolv_async *async)
{
  struct async_ares_ctx *ares = &async->ares;
  if(ares->temp_ai) {
    Curl_freeaddrinfo(ares->temp_ai);
    ares->temp_ai = NULL;
  }
#ifdef USE_HTTPSRR
  Curl_httpsrr_cleanup(&ares->hinfo);
#endif
}

void Curl_async_ares_shutdown(struct Curl_easy *data,
                             struct Curl_resolv_async *async)
{
  /* c-ares has a method to "cancel" operations on a channel, but
   * as reported in #18216, this does not totally reset the channel
   * and ares may get stuck.
   * We need to destroy the channel and on demand create a new
   * one to avoid that. */
  Curl_async_ares_destroy(data, async);
}

void Curl_async_ares_destroy(struct Curl_easy *data,
                             struct Curl_resolv_async *async)
{
  struct async_ares_ctx *ares = &async->ares;
  (void)data;
  if(ares->channel) {
    ares_destroy(ares->channel);
    ares->channel = NULL;
  }
  async_ares_cleanup(async);
}

/*
 * Curl_async_pollset() is called when someone from the outside world
 * (using curl_multi_fdset()) wants to get our fd_set setup.
 */

CURLcode Curl_async_pollset(struct Curl_easy *data, struct easy_pollset *ps)
{
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;
  if(ares && ares->channel)
    return Curl_ares_pollset(data, ares->channel, ps);
  return CURLE_OK;
}

/*
 * Curl_async_take_result() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_async_take_result(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                struct Curl_dns_entry **pdns)
{
  struct async_ares_ctx *ares = &async->ares;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(pdns);
  *pdns = NULL;
  if(!ares)
    return CURLE_FAILED_INIT;

  if(Curl_ares_perform(ares->channel, 0) < 0) {
    result = CURLE_UNRECOVERABLE_POLL;
    goto out;
  }

  if(!ares->num_pending) {
    /* all c-ares operations done, what is the result to report? */
    result = ares->result;
    if(ares->ares_status == ARES_SUCCESS && !result) {
      struct Curl_dns_entry *dns =
        Curl_dnscache_mk_entry(data, &ares->temp_ai,
                               async->hostname, async->port,
                               async->ip_version);
      if(!dns) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
#ifdef HTTPSRR_WORKS
      {
        struct Curl_https_rrinfo *lhrr = Curl_httpsrr_dup_move(&ares->hinfo);
        if(!lhrr)
          result = CURLE_OUT_OF_MEMORY;
        else
          dns->hinfo = lhrr;
      }
#endif
      if(!result) {
        result = Curl_dnscache_add(data, dns);
        *pdns = dns;
      }
    }
    /* if we have not found anything, report the proper
     * CURLE_COULDNT_RESOLVE_* code */
    if(!result && !*pdns) {
      const char *msg = NULL;
      if(ares->ares_status != ARES_SUCCESS)
        msg = ares_strerror(ares->ares_status);
      result = Curl_resolver_error(data, msg);
    }

    CURL_TRC_DNS(data, "is_resolved() result=%d, dns=%sfound",
                 result, *pdns ? "" : "not ");
    async_ares_cleanup(async);
  }
  else
    return CURLE_AGAIN;

out:
  ares->result = result;
  return result;
}

static timediff_t async_ares_poll_timeout(struct async_ares_ctx *ares,
                                          timediff_t timeout_ms)
{
  struct timeval *ares_calced, time_buf, max_timeout;
  int itimeout_ms;

#if TIMEDIFF_T_MAX > INT_MAX
    itimeout_ms = (timeout_ms > INT_MAX) ? INT_MAX :
                   ((timeout_ms < 0) ? -1 : (int)timeout_ms);
#else
    itimeout_ms = (int)timeout_ms;
#endif
  max_timeout.tv_sec = itimeout_ms / 1000;
  max_timeout.tv_usec = (itimeout_ms % 1000) * 1000;

  /* c-ares tells us the shortest timeout of any operation on channel */
  ares_calced = ares_timeout(ares->channel, &max_timeout, &time_buf);
  /* use the timeout period ares returned to us above if less than one
     second is left, otherwise use 1000ms to make sure the progress callback
     gets called frequent enough */
  if(!ares_calced->tv_sec)
    return (timediff_t)(ares_calced->tv_usec / 1000);
  else
    return 1000;
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
                          struct Curl_resolv_async *async,
                          struct Curl_dns_entry **pdns)
{
  struct async_ares_ctx *ares = &async->ares;
  struct curltime start = *Curl_pgrs_now(data);
  CURLcode result = CURLE_OK;

  DEBUGASSERT(pdns);
  *pdns = NULL; /* clear on entry */

  /* Wait for the name resolve query to complete or time out. */
  while(!result) {
    timediff_t timeout_ms;

    timeout_ms = Curl_timeleft_ms(data);
    if(!timeout_ms) { /* no applicable timeout from `data`*/
      timediff_t elapsed_ms = curlx_ptimediff_ms(Curl_pgrs_now(data), &start);
      if(elapsed_ms < (CURL_TIMEOUT_RESOLVE * 1000))
        timeout_ms = (CURL_TIMEOUT_RESOLVE * 1000) - elapsed_ms;
      else
        timeout_ms = -1;
    }

    if(timeout_ms < 0) {
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }

    if(Curl_ares_perform(ares->channel,
                         async_ares_poll_timeout(ares, timeout_ms)) < 0) {
      result = CURLE_UNRECOVERABLE_POLL;
      break;
    }

    result = Curl_async_take_result(data, async, pdns);
    if(result == CURLE_AGAIN)
      result = CURLE_OK;
    else if(result || *pdns)
      break;

    if(Curl_pgrsUpdate(data)) {
      result = CURLE_ABORTED_BY_CALLBACK;
      break;
    }
  }

  if(result)
    ares_cancel(ares->channel);
  return result;
}

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
    /* ignore elements with unsupported address family,
       settle family-specific sockaddr structure size. */
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

    ca = curlx_malloc(sizeof(struct Curl_addrinfo) + ss_size);
    if(!ca) {
      error = EAI_MEMORY;
      break;
    }

    /* copy each structure member individually, member ordering,
       size, or padding might be different for each platform. */

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
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;

  (void)timeouts;
  if(!ares)
    return;
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

#ifdef USE_HTTPSRR
static void async_ares_rr_done(void *user_data, ares_status_t status,
                               size_t timeouts,
                               const ares_dns_record_t *dnsrec)
{
  struct Curl_easy *data = user_data;
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;

  if(!ares)
    return;
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
 * Starts a name resolve for the given hostname and port number.
 */
CURLcode Curl_async_getaddrinfo(struct Curl_easy *data,
                                struct Curl_resolv_async *async)
{
  struct async_ares_ctx *ares = &async->ares;
#ifdef USE_HTTPSRR
  char *rrname = NULL;
#endif

  if(async_ares_init_lazy(data, async))
    return CURLE_FAILED_INIT;

#ifdef USE_HTTPSRR
  if(async->port != 443) {
    rrname = curl_maprintf("_%d._https.%s", async->port, async->hostname);
    if(!rrname)
      return CURLE_OUT_OF_MEMORY;
  }
#endif

  /* initial status - failed */
  ares->ares_status = ARES_ENOTFOUND;
  ares->result = CURLE_OK;

#if defined(CURLVERBOSE) && ARES_VERSION >= 0x011800 /* >= v1.24.0 */
  if(CURL_TRC_DNS_is_verbose(data)) {
    char *csv = ares_get_servers_csv(ares->channel);
    CURL_TRC_DNS(data, "asyn-ares: servers=%s", csv);
    ares_free_string(csv);
  }
#endif

  {
    struct ares_addrinfo_hints hints;
    char service[12];
    int pf = PF_INET;
    memset(&hints, 0, sizeof(hints));
#ifdef CURLRES_IPV6
    if((async->ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
      /* The stack seems to be IPv6-enabled */
      if(async->ip_version == CURL_IPRESOLVE_V6)
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
    curl_msnprintf(service, sizeof(service), "%d", async->port);
    ares->num_pending = 1;
    ares_getaddrinfo(ares->channel, async->hostname,
                     service, &hints, async_ares_addrinfo_cb, data);
  }

#ifdef USE_HTTPSRR
  {
    CURL_TRC_DNS(data, "asyn-ares: fire off query for HTTPSRR: %s",
                 rrname ? rrname : async->hostname);
    memset(&ares->hinfo, 0, sizeof(ares->hinfo));
    ares->hinfo.port = -1;
    ares->hinfo.rrname = rrname;
    ares->num_pending++; /* one more */
    ares_query_dnsrec(ares->channel,
                      rrname ? rrname : async->hostname,
                      ARES_CLASS_IN, ARES_REC_TYPE_HTTPS,
                      async_ares_rr_done, data, NULL);
  }
#endif

  return CURLE_OK;
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
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;
  CURLcode result = CURLE_NOT_BUILT_IN;
  const char *servers = data->set.str[STRING_DNS_SERVERS];
  int ares_result = ARES_SUCCESS;

#ifdef DEBUGBUILD
  if(getenv("CURL_DNS_SERVER"))
    servers = getenv("CURL_DNS_SERVER");
#endif

  if(!servers) {
    if(reset_on_null) {
      Curl_async_destroy(data);
    }
    return CURLE_OK;
  }

  /* if channel is not there, this is a parameter check */
  if(ares && ares->channel)
    ares_result = ares_set_servers_ports_csv(ares->channel, servers);
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
  return result;
}

CURLcode Curl_async_ares_set_dns_servers(struct Curl_easy *data)
{
  return async_ares_set_dns_servers(data, TRUE);
}

CURLcode Curl_async_ares_set_dns_interface(struct Curl_easy *data)
{
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;
  const char *interf = data->set.str[STRING_DNS_INTERFACE];

  if(!interf)
    interf = "";

  /* if channel is not there, this is a parameter check */
  if(ares && ares->channel)
    ares_set_local_dev(ares->channel, interf);

  return CURLE_OK;
}

CURLcode Curl_async_ares_set_dns_local_ip4(struct Curl_easy *data)
{
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;
  struct in_addr a4;
  const char *local_ip4 = data->set.str[STRING_DNS_LOCAL_IP4];

  if(!local_ip4 || (local_ip4[0] == 0)) {
    a4.s_addr = 0; /* disabled: do not bind to a specific address */
  }
  else {
    if(curlx_inet_pton(AF_INET, local_ip4, &a4) != 1) {
      DEBUGF(infof(data, "bad DNS IPv4 address"));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  /* if channel is not there yet, this is a parameter check */
  if(ares && ares->channel)
    ares_set_local_ip4(ares->channel, ntohl(a4.s_addr));

  return CURLE_OK;
}

CURLcode Curl_async_ares_set_dns_local_ip6(struct Curl_easy *data)
{
#ifdef USE_IPV6
  struct Curl_resolv_async *async = data->state.async;
  struct async_ares_ctx *ares = async ? &async->ares : NULL;
  unsigned char a6[INET6_ADDRSTRLEN];
  const char *local_ip6 = data->set.str[STRING_DNS_LOCAL_IP6];

  if(!local_ip6 || (local_ip6[0] == 0)) {
    /* disabled: do not bind to a specific address */
    memset(a6, 0, sizeof(a6));
  }
  else {
    if(curlx_inet_pton(AF_INET6, local_ip6, a6) != 1) {
      DEBUGF(infof(data, "bad DNS IPv6 address"));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }

  /* if channel is not there, this is a parameter check */
  if(ares && ares->channel)
    ares_set_local_ip6(ares->channel, a6);

  return CURLE_OK;
#else /* no IPv6 support */
  (void)data;
  return CURLE_NOT_BUILT_IN;
#endif
}

#endif /* USE_RESOLV_ARES */
