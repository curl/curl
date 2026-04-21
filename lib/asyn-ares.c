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

#ifdef USE_ARES

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
#endif

#define CARES_TIMEOUT_PER_ATTEMPT 2000

static int ares_ver = 0;

/*
 * Curl_async_global_init() - the generic low-level asynchronous name
 * resolve API. Called from curl_global_init() to initialize global resolver
 * environment. Initializes ares library.
 */
int Curl_async_ares_global_init(void)
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
void Curl_async_ares_global_cleanup(void)
{
#ifdef CARES_HAVE_ARES_LIBRARY_CLEANUP
  ares_library_cleanup();
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
  (void)data;
  if(async->ares.channel) {
    ares_destroy(async->ares.channel);
    async->ares.channel = NULL;
  }
}

/*
 * Curl_ares_pollset() is called when the outside world (using
 * curl_multi_fdset()) wants to get our fd_set setup and we are talking with
 * ares. The caller must make sure that this function is only called when we
 * have a working ares channel.
 *
 * Returns: sockets-in-use-bitmap
 */
static CURLcode async_ares_pollset(struct Curl_easy *data,
                                   ares_channel channel,
                                   struct easy_pollset *ps)
{
  curl_socket_t sockets[16];  /* ARES documented limit */
  unsigned int bitmap, i;
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
  return result;
}

timediff_t Curl_ares_timeout_ms(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                ares_channel channel)
{
  timediff_t async_timeout_ms;

  DEBUGASSERT(channel);
  if(!channel)
    return -1;

  async_timeout_ms = Curl_async_timeleft_ms(data, async);
  if((async_timeout_ms > 0) && (async_timeout_ms < INT_MAX)) {
    struct timeval timebuf;
    struct timeval *timeout;
    struct timeval end = { (int)async_timeout_ms / 1000,
                           ((int)async_timeout_ms % 1000) * 1000 };

    timeout = ares_timeout(channel, &end, &timebuf);
    if(timeout)
      return curlx_tvtoms(timeout);
  }
  return async_timeout_ms;
}

CURLcode Curl_async_ares_pollset(struct Curl_easy *data,
                                 struct Curl_resolv_async *async,
                                 struct easy_pollset *ps,
                                 timediff_t *ptimeout_ms)
{
  CURLcode result = CURLE_OK;

  *ptimeout_ms = 0;
  if(async->ares.channel && async->queries_ongoing) {
    result = async_ares_pollset(data, async->ares.channel, ps);
    if(!result)
      *ptimeout_ms = Curl_ares_timeout_ms(data, async, async->ares.channel);
  }
  return result;
}

timediff_t Curl_async_ares_poll_timeout(struct Curl_resolv_async *async,
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
  ares_calced = ares_timeout(async->ares.channel, &max_timeout, &time_buf);
  /* use the timeout period ares returned to us above if less than one
     second is left, otherwise use 1000ms to make sure the progress callback
     gets called frequent enough */
  if(!ares_calced->tv_sec)
    return (timediff_t)(ares_calced->tv_usec / 1000);
  else
    return 1000;
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
int Curl_ares_perform(ares_channel channel, timediff_t timeout_ms)
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
      pfd[i].events |= POLLRDNORM | POLLIN;
    }
    if(ARES_GETSOCK_WRITABLE(bitmask, i)) {
      pfd[i].fd = socks[i];
      pfd[i].events |= POLLWRNORM | POLLOUT;
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
    /* Call ares_process() unconditionally here, even if we timed out
       above, as otherwise the ares name resolve will not timeout! */
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  else {
    /* move through the descriptors and ask for processing on them */
    for(i = 0; i < num; i++)
      ares_process_fd(channel,
                      (pfd[i].revents & (POLLRDNORM | POLLIN)) ?
                      pfd[i].fd : ARES_SOCKET_BAD,
                      (pfd[i].revents & (POLLWRNORM | POLLOUT)) ?
                      pfd[i].fd : ARES_SOCKET_BAD);
  }
  return nfds;
}

const char *Curl_async_ares_err_msg(struct Curl_resolv_async *async)
{
  if(async->ares.status != ARES_SUCCESS)
    return ares_strerror(async->ares.status);
  return NULL;
}

#ifdef USE_HTTPSRR
static void async_ares_rr_done(void *user_data, ares_status_t status,
                               size_t timeouts,
                               const ares_dns_record_t *dnsrec)
{
  struct Curl_resolv_async *async = user_data;

  if(!async)
    return;

  (void)timeouts;
  async->dns_responses |= CURL_DNSQ_HTTPS;
  async->queries_ongoing--;
  if((ARES_SUCCESS != status) || !dnsrec)
    return;
  async->result = Curl_httpsrr_from_ares(dnsrec, &async->httpsrr);
}

CURLcode Curl_async_ares_query_httpsrr(struct Curl_easy *data,
                                       struct Curl_resolv_async *async)
{
  const char *query_name = async->hostname;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(!async->httpsrr_name);
  DEBUGASSERT(!async->httpsrr);

  if(async->port != 443) {
    async->httpsrr_name = curl_maprintf("_%d_.https.%s",
                                        async->port, async->hostname);
    if(!async->httpsrr_name)
      return CURLE_OUT_OF_MEMORY;
    query_name = async->httpsrr_name;
  }

  if(!async->ares.channel) {
    int status = ares_init_options(&async->ares.channel, NULL, 0);
    if(status != ARES_SUCCESS) {
      async->ares.channel = NULL;
      result = CURLE_FAILED_INIT;
      goto out;
    }
#ifdef DEBUGBUILD
    if(getenv("CURL_DNS_SERVER")) {
      const char *servers = getenv("CURL_DNS_SERVER");
      status = ares_set_servers_ports_csv(async->ares.channel, servers);
      if(status != ARES_SUCCESS) {
        result = CURLE_FAILED_INIT;
        goto out;
      }
    }
#endif
  }

  async->started = TRUE;
  async->queries_ongoing++;
  ares_query_dnsrec(async->ares.channel, query_name, ARES_CLASS_IN,
                    ARES_REC_TYPE_HTTPS,
                    async_ares_rr_done, async, NULL);
  CURL_TRC_DNS(data, "[HTTPS-RR] initiated request for %s", query_name);

out:
  if(result) {
    curlx_free(async->httpsrr_name);
    async->httpsrr_name = NULL;
  }
  return result;
}

#endif /* USE_HTTPSRR */

#ifdef USE_RESOLV_ARES

static CURLcode async_ares_set_dns_servers(struct Curl_easy *data,
                                           struct Curl_resolv_async *async);
static CURLcode async_ares_set_dns_interface(struct Curl_easy *data,
                                             struct Curl_resolv_async *async);
static CURLcode async_ares_set_dns_local_ip4(struct Curl_easy *data,
                                             struct Curl_resolv_async *async);
static CURLcode async_ares_set_dns_local_ip6(struct Curl_easy *data,
                                             struct Curl_resolv_async *async);

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
  int status;
  struct ares_options options;
  int optmask = ARES_OPT_SOCK_STATE_CB;
  CURLcode result = CURLE_OK;

  /* initial status - failed */
  async->ares.status = ARES_ENOTFOUND;
  async->queries_ongoing = 0;

  options.sock_state_cb = sock_state_cb;
  options.sock_state_cb_data = data;

  DEBUGASSERT(!async->ares.channel);
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

  status = ares_init_options(&async->ares.channel, &options, optmask);
  if(status != ARES_SUCCESS) {
    async->ares.channel = NULL;
    result = (status == ARES_ENOMEM) ? CURLE_OUT_OF_MEMORY : CURLE_FAILED_INIT;
    goto out;
  }

  result = async_ares_set_dns_servers(data, async);
  if(result && result != CURLE_NOT_BUILT_IN)
    goto out;

  result = async_ares_set_dns_interface(data, async);
  if(result && result != CURLE_NOT_BUILT_IN)
    goto out;

  result = async_ares_set_dns_local_ip4(data, async);
  if(result && result != CURLE_NOT_BUILT_IN)
    goto out;

  result = async_ares_set_dns_local_ip6(data, async);
  if(result && result != CURLE_NOT_BUILT_IN)
    goto out;

  result = CURLE_OK;

out:
  if(result && async->ares.channel) {
    ares_destroy(async->ares.channel);
    async->ares.channel = NULL;
  }
  return result;
}

/*
 * async_ares_node2addr() converts an address list provided by c-ares
 * to an internal libcurl compatible list.
 */
static struct Curl_addrinfo *async_ares_node2addr(
  struct ares_addrinfo_node *node)
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

static void async_ares_A_cb(void *user_data, int status, int timeouts,
                            struct ares_addrinfo *ares_ai)
{
  struct Curl_resolv_async *async = user_data;

  (void)timeouts;
  if(!async)
    return;

  async->dns_responses |= CURL_DNSQ_A;
  async->queries_ongoing--;
  if(status == ARES_SUCCESS) {
    async->ares.status = ARES_SUCCESS;
    async->res_A = async_ares_node2addr(ares_ai->nodes);
    ares_freeaddrinfo(ares_ai);
  }
  else if(async->ares.status != ARES_SUCCESS) /* do not overwrite success */
    async->ares.status = status;
}

#ifdef CURLRES_IPV6
static void async_ares_AAAA_cb(void *user_data, int status, int timeouts,
                               struct ares_addrinfo *ares_ai)
{
  struct Curl_resolv_async *async = user_data;

  (void)timeouts;
  if(!async)
    return;

  async->dns_responses |= CURL_DNSQ_AAAA;
  async->queries_ongoing--;
  if(status == ARES_SUCCESS) {
    async->ares.status = ARES_SUCCESS;
    async->res_AAAA = async_ares_node2addr(ares_ai->nodes);
    ares_freeaddrinfo(ares_ai);
  }
  else if(async->ares.status != ARES_SUCCESS) /* do not overwrite success */
    async->ares.status = status;
}
#endif /* CURLRES_IPV6 */

/*
 * Curl_async_getaddrinfo() - when using ares
 *
 * Starts a name resolve for the given hostname and port number.
 */
CURLcode Curl_async_getaddrinfo(struct Curl_easy *data,
                                struct Curl_resolv_async *async)
{
  char service[12];
  int socktype;
  CURLcode result = CURLE_OK;

  if(async->ares.channel) {
    DEBUGASSERT(0);
    result = CURLE_FAILED_INIT;
    goto out;
  }

  result = async_ares_init(data, async);
  if(result)
    goto out;

  result = Curl_resolv_announce_start(data, async->ares.channel);
  if(result)
    goto out;

#if defined(CURLVERBOSE) && ARES_VERSION >= 0x011800 /* >= v1.24.0 */
  if(CURL_TRC_DNS_is_verbose(data)) {
    char *csv = ares_get_servers_csv(async->ares.channel);
    CURL_TRC_DNS(data, "ares: servers=%s", csv);
    ares_free_string(csv);
  }
#endif

  curl_msnprintf(service, sizeof(service), "%d", async->port);
  socktype =
    (Curl_conn_get_transport(data, data->conn) == TRNSPRT_TCP) ?
    SOCK_STREAM : SOCK_DGRAM;

#ifdef CURLRES_IPV6
  if(async->dns_queries & CURL_DNSQ_AAAA) {
    struct ares_addrinfo_hints hints;

    memset(&hints, 0, sizeof(hints));
    CURL_TRC_DNS(data, "ares: query AAAA records for %s", async->hostname);
    hints.ai_family = PF_INET6;
    hints.ai_socktype = socktype;
    hints.ai_flags = ARES_AI_NUMERICSERV;
    async->started = TRUE;
    async->queries_ongoing++;
    ares_getaddrinfo(async->ares.channel, async->hostname,
                     service, &hints, async_ares_AAAA_cb, async);
  }
#endif /* CURLRES_IPV6 */

  if(async->dns_queries & CURL_DNSQ_A) {
    struct ares_addrinfo_hints hints;

    memset(&hints, 0, sizeof(hints));
    CURL_TRC_DNS(data, "ares: query A records for %s", async->hostname);
    hints.ai_family = PF_INET;
    hints.ai_socktype = socktype;
    hints.ai_flags = ARES_AI_NUMERICSERV;
    async->started = TRUE;
    async->queries_ongoing++;
    ares_getaddrinfo(async->ares.channel, async->hostname,
                     service, &hints, async_ares_A_cb, async);
  }

#ifdef USE_HTTPSRR
  if(async->dns_queries & CURL_DNSQ_HTTPS)
    result = Curl_async_ares_query_httpsrr(data, async);
#endif /* USE_HTTPSRR */

out:
  async->result = result;
  return result ? result : (async->queries_ongoing ? CURLE_AGAIN : CURLE_OK);
}

/* Set what DNS server are is to use. This is called in 2 situations:
 * 1. when the application does 'CURLOPT_DNS_SERVERS' and passing NULL
 *    means any previous set value should be unset. Which means
 *    we need to destroy and create the are channel anew, if there is one.
 * 2. When we lazy init the ares channel and NULL means that there
 *    are no preferences and we do not reset any existing channel. */
static CURLcode async_ares_set_dns_servers(struct Curl_easy *data,
                                           struct Curl_resolv_async *async)
{
  CURLcode result = CURLE_NOT_BUILT_IN;
  const char *servers = data->set.str[STRING_DNS_SERVERS];
  int ares_result = ARES_SUCCESS;

#ifdef DEBUGBUILD
  if(getenv("CURL_DNS_SERVER"))
    servers = getenv("CURL_DNS_SERVER");
#endif

  if(!servers)
    return CURLE_OK;

  /* if channel is not there, this is a parameter check */
  if(async && async->ares.channel)
    ares_result = ares_set_servers_ports_csv(async->ares.channel, servers);
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

static CURLcode async_ares_set_dns_interface(struct Curl_easy *data,
                                             struct Curl_resolv_async *async)
{
  const char *interf = data->set.str[STRING_DNS_INTERFACE];

  if(!interf)
    interf = "";

  /* if channel is not there, this is a parameter check */
  if(async && async->ares.channel)
    ares_set_local_dev(async->ares.channel, interf);

  return CURLE_OK;
}

static CURLcode async_ares_set_dns_local_ip4(struct Curl_easy *data,
                                             struct Curl_resolv_async *async)
{
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
  if(async && async->ares.channel)
    ares_set_local_ip4(async->ares.channel, ntohl(a4.s_addr));

  return CURLE_OK;
}

static CURLcode async_ares_set_dns_local_ip6(struct Curl_easy *data,
                                             struct Curl_resolv_async *async)
{
#ifdef USE_IPV6
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
  if(async && async->ares.channel)
    ares_set_local_ip6(async->ares.channel, a6);

  return CURLE_OK;
#else /* no IPv6 support */
  (void)data;
  (void)async;
  return CURLE_NOT_BUILT_IN;
#endif
}

#endif /* USE_RESOLV_ARES */
#endif /* USE_ARES */
