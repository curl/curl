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
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
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

#include <setjmp.h>  /* for sigjmp_buf, sigsetjmp() */
#include <signal.h>

#include "urldata.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "dnscache.h"
#include "hostip.h"
#include "httpsrr.h"
#include "url.h"
#include "multiif.h"
#include "progress.h"
#include "doh.h"
#include "select.h"
#include "strcase.h"
#include "easy_lock.h"
#include "curlx/inet_ntop.h"
#include "curlx/inet_pton.h"
#include "curlx/strcopy.h"
#include "curlx/strparse.h"

#if defined(CURLRES_SYNCH) &&                   \
  defined(HAVE_ALARM) &&                        \
  defined(SIGALRM) &&                           \
  defined(HAVE_SIGSETJMP) &&                    \
  defined(GLOBAL_INIT_IS_THREADSAFE)
/* alarm-based timeouts can only be used with all the dependencies satisfied */
#define USE_ALARM_TIMEOUT
#endif

#define MAX_HOSTCACHE_LEN (255 + 7) /* max FQDN + colon + port number + zero */

#define MAX_DNS_CACHE_SIZE 29999

#define RESOLV_FAIL(for_proxy) \
  ((for_proxy) ? CURLE_COULDNT_RESOLVE_PROXY : CURLE_COULDNT_RESOLVE_HOST)

#define IS_RESOLV_FAIL(result) \
  (((result) == CURLE_COULDNT_RESOLVE_HOST) || \
   ((result) == CURLE_COULDNT_RESOLVE_PROXY))
/*
 * ipv6works() returns TRUE if IPv6 seems to work.
 */
#ifdef USE_IPV6
static bool ipv6works(struct Curl_easy *data);
#else
#define ipv6works(x) FALSE
#endif

/*
 * hostip.c explained
 * ==================
 *
 * The main COMPILE-TIME DEFINES to keep in mind when reading the host*.c
 * source file are these:
 *
 * CURLRES_IPV6 - this host has getaddrinfo() and family, and thus we use
 * that. The host may not be able to resolve IPv6, but we do not really have to
 * take that into account. Hosts that are not IPv6-enabled have CURLRES_IPV4
 * defined.
 *
 * USE_RESOLV_ARES - is defined if libcurl is built to use c-ares for
 * asynchronous name resolves. This can be Windows or *nix.
 *
 * USE_RESOLV_THREADED - is defined if libcurl is built to run under (native)
 * Windows, and then the name resolve will be done in a new thread, and the
 * supported API will be the same as for ares-builds.
 *
 * If any of the two previous are defined, CURLRES_ASYNCH is defined too. If
 * libcurl is not built to use an asynchronous resolver, CURLRES_SYNCH is
 * defined.
 *
 * The host*.c sources files are split up like this:
 *
 * hostip.c   - method-independent resolver functions and utility functions
 * hostip4.c  - IPv4 specific functions
 * hostip6.c  - IPv6 specific functions
 * asyn.h     - common functions for all async resolvers
 * The two asynchronous name resolver backends are implemented in:
 * asyn-ares.c - async resolver using c-ares
 * asyn-thread.c - async resolver using POSIX threads
 *
 * The hostip.h is the united header file for all this. It defines the
 * CURLRES_* defines based on the config*.h and curl_setup.h defines.
 */

uint8_t Curl_resolv_dns_queries(struct Curl_easy *data, uint8_t ip_version)
{
  (void)data;
  switch(ip_version) {
  case CURL_IPRESOLVE_V6:
    return CURL_DNSQ_AAAA;
  case CURL_IPRESOLVE_V4:
    return CURL_DNSQ_A;
  default:
    if(ipv6works(data))
      return (CURL_DNSQ_A | CURL_DNSQ_AAAA);
    else
      return CURL_DNSQ_A;
  }
}

#ifdef CURLVERBOSE
const char *Curl_resolv_query_str(uint8_t dns_queries)
{
  switch(dns_queries) {
  case (CURL_DNSQ_A | CURL_DNSQ_AAAA | CURL_DNSQ_HTTPS):
    return "A+AAAA+HTTPS";
  case (CURL_DNSQ_A | CURL_DNSQ_AAAA):
    return "A+AAAA";
  case (CURL_DNSQ_AAAA | CURL_DNSQ_HTTPS):
    return "AAAA+HTTPS";
  case (CURL_DNSQ_AAAA):
    return "AAAA";
  case (CURL_DNSQ_A | CURL_DNSQ_HTTPS):
    return "A+HTTPS";
  case (CURL_DNSQ_A):
    return "A";
  case (CURL_DNSQ_HTTPS):
    return "HTTPS";
  case 0:
    return "-";
  default:
    DEBUGASSERT(0);
    return "???";
  }
}
#endif

/*
 * Curl_printable_address() stores a printable version of the 1st address
 * given in the 'ai' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 *
 * If the conversion fails, the target buffer is empty.
 */
void Curl_printable_address(const struct Curl_addrinfo *ai, char *buf,
                            size_t bufsize)
{
  DEBUGASSERT(bufsize);
  buf[0] = 0;

  switch(ai->ai_family) {
  case AF_INET: {
    const struct sockaddr_in *sa4 = (const void *)ai->ai_addr;
    const struct in_addr *ipaddr4 = &sa4->sin_addr;
    (void)curlx_inet_ntop(ai->ai_family, (const void *)ipaddr4, buf, bufsize);
    break;
  }
#ifdef USE_IPV6
  case AF_INET6: {
    const struct sockaddr_in6 *sa6 = (const void *)ai->ai_addr;
    const struct in6_addr *ipaddr6 = &sa6->sin6_addr;
    (void)curlx_inet_ntop(ai->ai_family, (const void *)ipaddr6, buf, bufsize);
    break;
  }
#endif
  default:
    break;
  }
}

#ifdef USE_ALARM_TIMEOUT
/* Beware this is a global and unique instance. This is used to store the
   return address that we can jump back to from inside a signal handler. This
   is not thread-safe stuff. */
static sigjmp_buf curl_jmpenv;
static curl_simple_lock curl_jmpenv_lock = CURL_SIMPLE_LOCK_INIT;
#endif

#ifdef USE_IPV6
/* return a static IPv6 ::1 for the name */
static struct Curl_addrinfo *get_localhost6(uint16_t port, const char *name)
{
  struct Curl_addrinfo *ca;
  const size_t ss_size = sizeof(struct sockaddr_in6);
  const size_t hostlen = strlen(name);
  struct sockaddr_in6 sa6;
  unsigned char ipv6[16];
  unsigned short port16 = (unsigned short)(port & 0xffff);
  ca = curlx_calloc(1, sizeof(struct Curl_addrinfo) + ss_size + hostlen + 1);
  if(!ca)
    return NULL;

  memset(&sa6, 0, sizeof(sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons(port16);

  (void)curlx_inet_pton(AF_INET6, "::1", ipv6);
  memcpy(&sa6.sin6_addr, ipv6, sizeof(ipv6));

  ca->ai_flags     = 0;
  ca->ai_family    = AF_INET6;
  ca->ai_socktype  = SOCK_STREAM;
  ca->ai_protocol  = IPPROTO_TCP;
  ca->ai_addrlen   = (curl_socklen_t)ss_size;
  ca->ai_next      = NULL;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Curl_addrinfo));
  memcpy(ca->ai_addr, &sa6, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  curlx_strcopy(ca->ai_canonname, hostlen + 1, name, hostlen);
  return ca;
}
#else
#define get_localhost6(x, y) NULL
#endif

/* return a static IPv4 127.0.0.1 for the given name */
static struct Curl_addrinfo *get_localhost(uint16_t port, const char *name)
{
  struct Curl_addrinfo *ca;
  struct Curl_addrinfo *ca6;
  const size_t ss_size = sizeof(struct sockaddr_in);
  const size_t hostlen = strlen(name);
  struct sockaddr_in sa;
  unsigned int ipv4;
  unsigned short port16 = (unsigned short)(port & 0xffff);

  /* memset to clear the sa.sin_zero field */
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port16);
  if(curlx_inet_pton(AF_INET, "127.0.0.1", (char *)&ipv4) < 1)
    return NULL;
  memcpy(&sa.sin_addr, &ipv4, sizeof(ipv4));

  ca = curlx_calloc(1, sizeof(struct Curl_addrinfo) + ss_size + hostlen + 1);
  if(!ca)
    return NULL;
  ca->ai_flags     = 0;
  ca->ai_family    = AF_INET;
  ca->ai_socktype  = SOCK_STREAM;
  ca->ai_protocol  = IPPROTO_TCP;
  ca->ai_addrlen   = (curl_socklen_t)ss_size;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Curl_addrinfo));
  memcpy(ca->ai_addr, &sa, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  curlx_strcopy(ca->ai_canonname, hostlen + 1, name, hostlen);

  ca6 = get_localhost6(port, name);
  if(!ca6)
    return ca;
  ca6->ai_next = ca;
  return ca6;
}

#ifdef USE_IPV6
/* the nature of most systems is that IPv6 status does not come and go during a
   program's lifetime so we only probe the first time and then we have the
   info kept for fast reuse */
CURLcode Curl_probeipv6(struct Curl_multi *multi)
{
  /* probe to see if we have a working IPv6 stack */
  curl_socket_t s = CURL_SOCKET(PF_INET6, SOCK_DGRAM, 0);
  multi->ipv6_works = FALSE;
  if(s == CURL_SOCKET_BAD) {
    if(SOCKERRNO == SOCKENOMEM)
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    multi->ipv6_works = TRUE;
    sclose(s);
  }
  return CURLE_OK;
}

/*
 * ipv6works() returns TRUE if IPv6 seems to work.
 */
static bool ipv6works(struct Curl_easy *data)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  return data ? data->multi->ipv6_works : FALSE;
}
#endif /* USE_IPV6 */

/*
 * Curl_host_is_ipnum() returns TRUE if the given string is a numerical IPv4
 * (or IPv6 if supported) address.
 */
bool Curl_host_is_ipnum(const char *hostname)
{
  struct in_addr in;
#ifdef USE_IPV6
  struct in6_addr in6;
#endif
  if(curlx_inet_pton(AF_INET, hostname, &in) > 0
#ifdef USE_IPV6
     || curlx_inet_pton(AF_INET6, hostname, &in6) > 0
#endif
    )
    return TRUE;
  return FALSE;
}

/* return TRUE if 'part' is a case insensitive tail of 'full' */
static bool tailmatch(const char *full, size_t flen,
                      const char *part, size_t plen)
{
  if(plen > flen)
    return FALSE;
  return curl_strnequal(part, &full[flen - plen], plen);
}

static CURLcode hostip_resolv_failed(struct Curl_easy *data,
                                     const char *hostname,
                                     bool for_proxy)
{
  failf(data, "Could not resolve %s: %s",
        for_proxy ? "proxy" : "host", hostname);
  return RESOLV_FAIL(for_proxy);
}

static bool can_resolve_dns_queries(struct Curl_easy *data,
                                    uint8_t dns_queries)
{
  (void)data;
  if((CURL_DNSQ_IP(dns_queries) == CURL_DNSQ_AAAA) && !ipv6works(data))
    return FALSE;
  return TRUE;
}

CURLcode Curl_resolv_announce_start(struct Curl_easy *data,
                                    void *resolver)
{
  if(data->set.resolver_start) {
    int rc;

    CURL_TRC_DNS(data, "announcing resolve to application");
    Curl_set_in_callback(data, TRUE);
    rc = data->set.resolver_start(resolver, NULL,
                                  data->set.resolver_start_client);
    Curl_set_in_callback(data, FALSE);
    if(rc) {
      CURL_TRC_DNS(data, "application aborted resolve");
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }
  return CURLE_OK;
}

#ifdef USE_CURL_ASYNC

static struct Curl_resolv_async *hostip_async_new(struct Curl_easy *data,
                                                  uint8_t dns_queries,
                                                  const char *hostname,
                                                  uint16_t port,
                                                  uint8_t transport,
                                                  bool for_proxy,
                                                  timediff_t timeout_ms)
{
  struct Curl_resolv_async *async;
  size_t hostlen = strlen(hostname);

  if(!data->multi) {
    DEBUGASSERT(0);
    return NULL;
  }

  /* struct size already includes the NUL for hostname */
  async = curlx_calloc(1, sizeof(*async) + hostlen);
  if(!async)
    return NULL;

  /* Give every async resolve operation a "unique" id. This may
   * wrap around after a long time, making collisions highly unlikely.
   * As we keep the async structs at the easy handle, chances of
   * easy `mid plus resolv->id` colliding should be astronomical.
   * `resolv_id == 0` is never used. */
  if(data->multi->last_resolv_id == UINT32_MAX)
    data->multi->last_resolv_id = 1; /* wrap around */
  else
    data->multi->last_resolv_id++;
  async->id = data->multi->last_resolv_id;
  async->dns_queries = dns_queries;
  async->port = port;
  async->transport = transport;
  async->for_proxy = for_proxy;
  async->start = *Curl_pgrs_now(data);
  async->timeout_ms = timeout_ms;
  if(hostlen) {
    memcpy(async->hostname, hostname, hostlen);
    async->is_ipaddr = Curl_is_ipaddr(async->hostname);
    if(async->is_ipaddr)
      async->is_ipv4addr = Curl_is_ipv4addr(async->hostname);
  }

  return async;
}

static CURLcode hostip_resolv_take_result(struct Curl_easy *data,
                                          struct Curl_resolv_async *async,
                                          struct Curl_dns_entry **pdns)
{
  CURLcode result;

  /* If async resolving is ongoing, this must be set */
  if(!async)
    return CURLE_FAILED_INIT;

#ifndef CURL_DISABLE_DOH
  if(async->doh)
    result = Curl_doh_take_result(data, async, pdns);
  else
#endif
  result = Curl_async_take_result(data, async, pdns);

  if(result == CURLE_AGAIN) {
    CURL_TRC_DNS(data, "resolve incomplete, queries=%s, responses=%s, "
                 "ongoing=%d for %s:%d",
                 Curl_resolv_query_str(async->dns_queries),
                 Curl_resolv_query_str(async->dns_responses),
                 async->queries_ongoing, async->hostname, async->port);
    result = CURLE_OK;
  }
  else if(result) {
    result = Curl_async_failed(data, async, NULL);
  }
  else {
    CURL_TRC_DNS(data, "resolve complete for %s:%u",
                 async->hostname, async->port);
    DEBUGASSERT(*pdns);
  }

  return result;
}

timediff_t Curl_resolv_elapsed_ms(struct Curl_easy *data,
                                  uint32_t resolv_id)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  if(!async)
    return CURL_TIMEOUT_RESOLVE_MS;
  return curlx_ptimediff_ms(Curl_pgrs_now(data), &async->start);
}

bool Curl_resolv_has_answers(struct Curl_easy *data,
                             uint32_t resolv_id, uint8_t dns_queries)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  uint8_t check_queries;
  /* a no longer existing/running resolve has all answers. */
  if(!async || async->done)
    return TRUE;
  /* Relevant are only queries undertaken. Others are considered answered. */
  check_queries = (dns_queries & async->dns_queries);
  if((check_queries & async->dns_responses) != check_queries) {
    return FALSE;
  }
  return TRUE;
}

const struct Curl_addrinfo *Curl_resolv_get_ai(struct Curl_easy *data,
                                               uint32_t resolv_id,
                                               int ai_family,
                                               unsigned int index)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  (void)index;
  if(!async)
    return NULL;
  if((ai_family == AF_INET) && !(async->dns_queries & CURL_DNSQ_A))
    return NULL;
#ifdef USE_IPV6
  if((ai_family == AF_INET6) && !(async->dns_queries & CURL_DNSQ_AAAA))
    return NULL;
#endif
  return Curl_async_get_ai(data, async, ai_family, index);
}


#ifdef USE_HTTPSRR
const struct Curl_https_rrinfo *
Curl_resolv_get_https(struct Curl_easy *data, uint32_t resolv_id)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  if(!async)
    return NULL;
  return Curl_async_get_https(data, async);
}

bool Curl_resolv_knows_https(struct Curl_easy *data, uint32_t resolv_id)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  if(!async)
    return TRUE;
  return Curl_async_knows_https(data, async);
}

#endif /* USE_HTTPSRR */

#endif /* USE_CURL_ASYNC */

static CURLcode hostip_resolv_start(struct Curl_easy *data,
                                    uint8_t dns_queries,
                                    const char *hostname,
                                    uint16_t port,
                                    uint8_t transport,
                                    bool for_proxy,
                                    timediff_t timeout_ms,
                                    bool allowDOH,
                                    uint32_t *presolv_id,
                                    struct Curl_dns_entry **pdns)
{
#ifdef USE_CURL_ASYNC
  struct Curl_resolv_async *async = NULL;
#endif
  struct Curl_addrinfo *addr = NULL;
  size_t hostname_len;
  CURLcode result = CURLE_OK;

  (void)timeout_ms; /* not in all ifdefs */
  *presolv_id = 0;
  *pdns = NULL;

  /* Check for "known" things to resolve ourselves. */
#ifndef USE_RESOLVE_ON_IPS
  if(Curl_is_ipaddr(hostname)) {
    /* test655 verifies that the announce is done, even though there
     * is no real resolving. So, keep doing this. */
    result = Curl_resolv_announce_start(data, NULL);
    if(result)
      goto out;
    /* shortcut literal IP addresses, if we are not told to resolve them. */
    result = Curl_str2addr(hostname, port, &addr);
    goto out;
  }
#endif

  hostname_len = strlen(hostname);
  if(curl_strequal(hostname, "localhost") ||
     curl_strequal(hostname, "localhost.") ||
     tailmatch(hostname, hostname_len, STRCONST(".localhost")) ||
     tailmatch(hostname, hostname_len, STRCONST(".localhost."))) {
    result = Curl_resolv_announce_start(data, NULL);
    if(result)
      goto out;
    addr = get_localhost(port, hostname);
    if(!addr)
      result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

#ifndef CURL_DISABLE_DOH
  if(!Curl_is_ipaddr(hostname) && allowDOH && data->set.doh) {
    result = Curl_resolv_announce_start(data, NULL);
    if(result)
      goto out;
    if(!async) {
      async = hostip_async_new(data, dns_queries, hostname, port,
                               transport, for_proxy, timeout_ms);
      if(!async) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
    }
    result = Curl_doh(data, async);
    goto out;
  }
#else
  (void)allowDOH;
#endif

  /* Can we provide the requested IP specifics in resolving? */
  if(!can_resolve_dns_queries(data, dns_queries)) {
    result = RESOLV_FAIL(for_proxy);
    goto out;
  }

#ifdef CURLRES_ASYNCH
  (void)addr;
  if(!async) {
    async = hostip_async_new(data, dns_queries, hostname, port,
                             transport, for_proxy, timeout_ms);
    if(!async) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }
  result = Curl_async_getaddrinfo(data, async);
  if(result == CURLE_AGAIN) {
    /* the answer might be there already. Check. */
    CURLcode r2 = hostip_resolv_take_result(data, async, pdns);
    if(r2)
      result = r2;
    else if(*pdns)
      result = CURLE_OK;
  }
#else
  result = Curl_resolv_announce_start(data, NULL);
  if(result)
    goto out;
  addr = Curl_sync_getaddrinfo(data, dns_queries, hostname, port, transport);
  if(!addr)
    result = RESOLV_FAIL(for_proxy);
#endif

out:
  if(!result) {
    if(addr) {
      /* we got a response, create a dns entry, add to cache, return */
      DEBUGASSERT(!*pdns);
      *pdns = Curl_dnscache_mk_entry(data, dns_queries, &addr, hostname, port);
      if(!*pdns)
        result = CURLE_OUT_OF_MEMORY;
    }
    else if(!*pdns)
      result = CURLE_AGAIN;
  }
  else if(*pdns)
    Curl_dns_entry_unlink(data, pdns);
  else if(addr)
    Curl_freeaddrinfo(addr);

#ifdef USE_CURL_ASYNC
  if(async) {
    if(result == CURLE_AGAIN) { /* still need it, link, return id. */
      *presolv_id = async->id;
      async->next = data->state.async;
      data->state.async = async;
    }
    else {
      Curl_async_destroy(data, async);
    }
  }
#endif
  return result;
}

static CURLcode hostip_resolv(struct Curl_easy *data,
                              uint8_t dns_queries,
                              const char *hostname,
                              uint16_t port,
                              uint8_t transport,
                              bool for_proxy,
                              timediff_t timeout_ms,
                              bool allowDOH,
                              uint32_t *presolv_id,
                              struct Curl_dns_entry **pdns)
{
  size_t hostname_len;
  CURLcode result = RESOLV_FAIL(for_proxy);
  bool cache_dns = FALSE;

  (void)timeout_ms; /* not used in all ifdefs */
  *presolv_id = 0;
  *pdns = NULL;

#ifdef CURL_DISABLE_DOH
  (void)allowDOH;
#endif

  /* We should intentionally error and not resolve .onion TLDs */
  hostname_len = strlen(hostname);
  DEBUGASSERT(hostname_len);
  if(hostname_len >= 7 &&
     (curl_strequal(&hostname[hostname_len - 6], ".onion") ||
      curl_strequal(&hostname[hostname_len - 7], ".onion."))) {
    failf(data, "Not resolving .onion address (RFC 7686)");
    goto out;
  }

#ifdef DEBUGBUILD
  CURL_TRC_DNS(data, "hostip_resolv(%s:%u, queries=%s)",
               hostname, port, Curl_resolv_query_str(dns_queries));
  if((CURL_DNSQ_IP(dns_queries) == CURL_DNSQ_AAAA) &&
     getenv("CURL_DBG_RESOLV_FAIL_IPV6")) {
    infof(data, "DEBUG fail ipv6 resolve");
    result = hostip_resolv_failed(data, hostname, for_proxy);
    goto out;
  }
#endif
  /* Let's check our DNS cache first */
  result = Curl_dnscache_get(data, dns_queries, hostname, port, pdns);
  if(*pdns) {
    infof(data, "Hostname %s was found in DNS cache", hostname);
    result = CURLE_OK;
  }
  else if(result) {
    infof(data, "Negative DNS entry");
    result = hostip_resolv_failed(data, hostname, for_proxy);
  }
  else {
    /* No luck, we need to start resolving. */
    cache_dns = TRUE;
    result = hostip_resolv_start(data, dns_queries, hostname, port,
                                 transport, for_proxy, timeout_ms, allowDOH,
                                 presolv_id, pdns);
  }

out:
  if(result && (result != CURLE_AGAIN)) {
    Curl_dns_entry_unlink(data, pdns);
    if(IS_RESOLV_FAIL(result)) {
      if(cache_dns)
        Curl_dnscache_add_negative(data, dns_queries, hostname, port);
      failf(data, "Could not resolve: %s:%u", hostname, port);
    }
    else {
      failf(data, "Error %d resolving %s:%u", result, hostname, port);
    }
  }
  else if(cache_dns && *pdns) {
    result = Curl_dnscache_add(data, *pdns);
    if(result)
      Curl_dns_entry_unlink(data, pdns);
  }

  return result;
}

CURLcode Curl_resolv_blocking(struct Curl_easy *data,
                              uint8_t dns_queries,
                              const char *hostname,
                              uint16_t port,
                              uint8_t transport,
                              struct Curl_dns_entry **pdns)
{
  CURLcode result;
  uint32_t resolv_id;
  DEBUGASSERT(hostname && *hostname);
  *pdns = NULL;
  /* We cannot do a blocking resolve using DoH currently */
  result = hostip_resolv(data, dns_queries,
                         hostname, port, transport, FALSE, 0, FALSE,
                         &resolv_id, pdns);
  switch(result) {
  case CURLE_OK:
    DEBUGASSERT(*pdns);
    break;
#ifdef USE_CURL_ASYNC
  case CURLE_AGAIN:
    DEBUGASSERT(!*pdns);
    result = Curl_async_await(data, resolv_id, pdns);
    Curl_resolv_destroy(data, resolv_id);
    break;
#endif
  default:
    break;
  }
  return result;
}

#ifdef USE_ALARM_TIMEOUT
/*
 * This signal handler jumps back into the main libcurl code and continues
 * execution. This effectively causes the remainder of the application to run
 * within a signal handler which is nonportable and could lead to problems.
 */
CURL_NORETURN static void alarmfunc(int sig)
{
  (void)sig;
  siglongjmp(curl_jmpenv, 1);
}
#endif /* USE_ALARM_TIMEOUT */

#ifdef USE_ALARM_TIMEOUT

static CURLcode resolv_alarm_timeout(struct Curl_easy *data,
                                     uint8_t dns_queries,
                                     const char *hostname,
                                     uint16_t port,
                                     uint8_t transport,
                                     bool for_proxy,
                                     timediff_t timeout_ms,
                                     uint32_t *presolv_id,
                                     struct Curl_dns_entry **entry)
{
#ifdef HAVE_SIGACTION
  struct sigaction keep_sigact; /* store the old struct here */
  volatile bool keep_copysig = FALSE; /* whether old sigact has been saved */
  struct sigaction sigact;
#else
#ifdef HAVE_SIGNAL
  void (*keep_sigact)(int);       /* store the old handler here */
#endif /* HAVE_SIGNAL */
#endif /* HAVE_SIGACTION */
  volatile long timeout;
  volatile unsigned int prev_alarm = 0;
  CURLcode result;

  DEBUGASSERT(hostname && *hostname);
  DEBUGASSERT(timeout_ms > 0);
  DEBUGASSERT(!data->set.no_signal);
#ifndef CURL_DISABLE_DOH
  DEBUGASSERT(!data->set.doh);
#endif

  *entry = NULL;
  timeout = (timeout_ms > LONG_MAX) ? LONG_MAX : (long)timeout_ms;
  if(timeout < 1000) {
    /* The alarm() function only provides integer second resolution, so if
       we want to wait less than one second we must bail out already now. */
    failf(data,
          "remaining timeout of %ld too small to resolve via SIGALRM method",
          timeout);
    return CURLE_OPERATION_TIMEDOUT;
  }
  /* This allows us to time-out from the name resolver, as the timeout
     will generate a signal and we will siglongjmp() from that here.
     This technique has problems (see alarmfunc).
     This should be the last thing we do before calling Curl_resolv(),
     as otherwise we would have to worry about variables that get modified
     before we invoke Curl_resolv() (and thus use "volatile"). */
  curl_simple_lock_lock(&curl_jmpenv_lock);

  if(sigsetjmp(curl_jmpenv, 1)) {
    /* this is coming from a siglongjmp() after an alarm signal */
    failf(data, "name lookup timed out");
    result = CURLE_OPERATION_TIMEDOUT;
    goto clean_up;
  }
  else {
    /*************************************************************
     * Set signal handler to catch SIGALRM
     * Store the old value to be able to set it back later!
     *************************************************************/
#ifdef HAVE_SIGACTION
    sigaction(SIGALRM, NULL, &sigact);
    keep_sigact = sigact;
    keep_copysig = TRUE; /* yes, we have a copy */
    sigact.sa_handler = alarmfunc;
#ifdef SA_RESTART
    /* HP-UX does not have SA_RESTART but defaults to that behavior! */
    sigact.sa_flags &= ~SA_RESTART;
#endif
    /* now set the new struct */
    sigaction(SIGALRM, &sigact, NULL);
#else /* HAVE_SIGACTION */
    /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
    keep_sigact = signal(SIGALRM, alarmfunc);
#endif
#endif /* HAVE_SIGACTION */

    /* alarm() makes a signal get sent when the timeout fires off, and that
       will abort system calls */
    prev_alarm = alarm(curlx_sltoui(timeout / 1000L));
  }

  /* Perform the actual name resolution. This might be interrupted by an
   * alarm if it takes too long. */
  result = hostip_resolv(data, dns_queries, hostname, port, transport,
                         for_proxy, timeout_ms, FALSE, presolv_id, entry);

clean_up:
  if(!prev_alarm)
    /* deactivate a possibly active alarm before uninstalling the handler */
    alarm(0);

#ifdef HAVE_SIGACTION
  if(keep_copysig) {
    /* we got a struct as it looked before, now put that one back nice
       and clean */
    sigaction(SIGALRM, &keep_sigact, NULL); /* put it back */
  }
#else
#ifdef HAVE_SIGNAL
  /* restore the previous SIGALRM handler */
  signal(SIGALRM, keep_sigact);
#endif
#endif /* HAVE_SIGACTION */

  curl_simple_lock_unlock(&curl_jmpenv_lock);

  /* switch back the alarm() to either zero or to what it was before minus
     the time we spent until now! */
  if(prev_alarm) {
    /* there was an alarm() set before us, now put it back */
    timediff_t elapsed_secs = curlx_ptimediff_ms(Curl_pgrs_now(data),
                                                 &data->conn->created) / 1000;

    /* the alarm period is counted in even number of seconds */
    unsigned long alarm_set = (unsigned long)(prev_alarm - elapsed_secs);

    if(!alarm_set ||
       ((alarm_set >= 0x80000000) && (prev_alarm < 0x80000000))) {
      /* if the alarm time-left reached zero or turned "negative" (counted
         with unsigned values), we should fire off a SIGALRM here, but we
         will not, and zero would be to switch it off so we never set it to
         less than 1! */
      alarm(1);
      result = CURLE_OPERATION_TIMEDOUT;
      failf(data, "Previous alarm fired off");
    }
    else
      alarm((unsigned int)alarm_set);
  }

  return result;
}

#endif /* USE_ALARM_TIMEOUT */

/*
 * Curl_resolv() is the main name resolve function within libcurl. It resolves
 * a name and returns a pointer to the entry in the 'entry' argument. This
 * function might return immediately if we are using asynch resolves. See the
 * return codes.
 *
 * The cache entry we return will get its 'inuse' counter increased when this
 * function is used. You MUST call Curl_dns_entry_unlink() later (when you are
 * done using this struct) to decrease the reference counter again.
 *
 * If built with a synchronous resolver and use of signals is not
 * disabled by the application, then a nonzero timeout will cause a
 * timeout after the specified number of milliseconds. Otherwise, timeout
 * is ignored.
 *
 * Return codes:
 * CURLE_OK = success, *pdns set to non-NULL
 * CURLE_AGAIN = resolving in progress, *pdns == NULL
 * any other CURLcode error, *pdns == NULL
 */
CURLcode Curl_resolv(struct Curl_easy *data,
                     uint8_t dns_queries,
                     const char *hostname,
                     uint16_t port,
                     uint8_t transport,
                     bool for_proxy,
                     timediff_t timeout_ms,
                     uint32_t *presolv_id,
                     struct Curl_dns_entry **pdns)
{
  DEBUGASSERT(hostname && *hostname);
  *presolv_id = 0;
  *pdns = NULL;

  if(timeout_ms < 0)
    /* got an already expired timeout */
    return CURLE_OPERATION_TIMEDOUT;
  else if(!timeout_ms)
    timeout_ms = CURL_TIMEOUT_RESOLVE_MS;

#ifdef USE_ALARM_TIMEOUT
  if(timeout_ms && data->set.no_signal) {
    /* Cannot use ALARM when signals are disabled */
    timeout_ms = 0;
  }
  if(timeout_ms && !Curl_doh_wanted(data)) {
    return resolv_alarm_timeout(data, dns_queries, hostname, port, transport,
                                for_proxy, timeout_ms, presolv_id, pdns);
  }
#endif /* !USE_ALARM_TIMEOUT */

#ifndef CURLRES_ASYNCH
  if(timeout_ms)
    infof(data, "timeout on name lookup is not supported");
#endif

  return hostip_resolv(data, dns_queries, hostname, port, transport,
                       for_proxy, timeout_ms, TRUE, presolv_id, pdns);
}

#ifdef USE_CURL_ASYNC

struct Curl_resolv_async *Curl_async_get(struct Curl_easy *data,
                                         uint32_t resolv_id)
{
  struct Curl_resolv_async *async = data->state.async;
  for(; async; async = async->next) {
    if(async->id == resolv_id)
      return async;
  }
  return NULL;
}

CURLcode Curl_resolv_take_result(struct Curl_easy *data, uint32_t resolv_id,
                                 struct Curl_dns_entry **pdns)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  CURLcode result;

  /* If async resolving is ongoing, this must be set */
  if(!async)
    return CURLE_FAILED_INIT;

  /* check if we have the name resolved by now (from someone else) */
  result = Curl_dnscache_get(data, async->dns_queries,
                             async->hostname, async->port, pdns);
  if(*pdns) {
    /* Tell a possibly async resolver we no longer need the results. */
    infof(data, "Hostname '%s' was found in DNS cache", async->hostname);
    Curl_async_shutdown(data, async);
    return CURLE_OK;
  }
  else if(result) {
    Curl_async_shutdown(data, async);
    return Curl_async_failed(data, async, NULL);
  }

  result = hostip_resolv_take_result(data, async, pdns);

  if(*pdns) {
    /* Add to cache */
    result = Curl_dnscache_add(data, *pdns);
    if(result)
      Curl_dns_entry_unlink(data, pdns);
  }
  else if(IS_RESOLV_FAIL(result)) {
    Curl_dnscache_add_negative(data, async->dns_queries,
                               async->hostname, async->port);
    failf(data, "Could not resolve: %s:%u", async->hostname, async->port);
  }
  else if(result) {
    failf(data, "Error %d resolving %s:%u",
          result, async->hostname, async->port);
  }
  return result;
}

CURLcode Curl_resolv_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps)
{
  struct Curl_resolv_async *async = data->state.async;
  CURLcode result = CURLE_OK;

  (void)ps;
  for(; async && !result; async = async->next) {
#ifndef CURL_DISABLE_DOH
    if(async->doh) /* DoH has nothing for the pollset */
      continue;
#endif
    result = Curl_async_pollset(data, async, ps);
  }
  return result;
}

void Curl_resolv_destroy(struct Curl_easy *data, uint32_t resolv_id)
{
  struct Curl_resolv_async **panchor = &data->state.async;

  for(; *panchor; panchor = &(*panchor)->next) {
    struct Curl_resolv_async *async = *panchor;
    if(async->id == resolv_id) {
      *panchor = async->next;
      Curl_async_destroy(data, async);
      break;
    }
  }
}

void Curl_resolv_shutdown_all(struct Curl_easy *data)
{
  struct Curl_resolv_async *async = data->state.async;
  for(; async; async = async->next) {
    Curl_async_shutdown(data, async);
  }
}

void Curl_resolv_destroy_all(struct Curl_easy *data)
{
  while(data->state.async) {
    struct Curl_resolv_async *async = data->state.async;
    data->state.async = async->next;
    Curl_async_destroy(data, async);
  }
}

#endif /* USE_CURL_ASYNC */

#ifdef USE_UNIX_SOCKETS
CURLcode Curl_resolv_unix(struct Curl_easy *data,
                          const char *unix_path,
                          bool abstract_path,
                          struct Curl_dns_entry **pdns)
{
  struct Curl_addrinfo *addr;
  CURLcode result;

  DEBUGASSERT(unix_path);
  *pdns = NULL;

  result = Curl_unix2addr(unix_path, abstract_path, &addr);
  if(result) {
    if(result == CURLE_TOO_LARGE) {
      /* Long paths are not supported for now */
      failf(data, "Unix socket path too long: '%s'", unix_path);
      result = CURLE_COULDNT_RESOLVE_HOST;
    }
    return result;
  }

  *pdns = Curl_dnscache_mk_entry(data, 0, &addr, NULL, 0);
  return *pdns ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}
#endif /* USE_UNIX_SOCKETS */
