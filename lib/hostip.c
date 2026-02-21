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
#include "doh.h"
#include "progress.h"
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
 * CURLRES_ARES - is defined if libcurl is built to use c-ares for
 * asynchronous name resolves. This can be Windows or *nix.
 *
 * CURLRES_THREADED - is defined if libcurl is built to run under (native)
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

#ifdef CURLVERBOSE
static void show_resolve_info(struct Curl_easy *data,
                              struct Curl_dns_entry *dns)
{
  const struct Curl_addrinfo *a;
  CURLcode result = CURLE_OK;
#ifdef CURLRES_IPV6
  struct dynbuf out[2];
#else
  struct dynbuf out[1];
#endif
  DEBUGASSERT(data);
  DEBUGASSERT(dns);

  if(!data->set.verbose ||
     /* ignore no name or numerical IP addresses */
     !dns->hostname[0] || Curl_host_is_ipnum(dns->hostname))
    return;

  a = dns->addr;

  infof(data, "Host %s:%d was resolved.",
        (dns->hostname[0] ? dns->hostname : "(none)"), dns->port);

  curlx_dyn_init(&out[0], 1024);
#ifdef CURLRES_IPV6
  curlx_dyn_init(&out[1], 1024);
#endif

  while(a) {
    if(
#ifdef CURLRES_IPV6
       a->ai_family == PF_INET6 ||
#endif
       a->ai_family == PF_INET) {
      char buf[MAX_IPADR_LEN];
      struct dynbuf *d = &out[(a->ai_family != PF_INET)];
      Curl_printable_address(a, buf, sizeof(buf));
      if(curlx_dyn_len(d))
        result = curlx_dyn_addn(d, ", ", 2);
      if(!result)
        result = curlx_dyn_add(d, buf);
      if(result) {
        infof(data, "too many IP, cannot show");
        goto fail;
      }
    }
    a = a->ai_next;
  }

#ifdef CURLRES_IPV6
  infof(data, "IPv6: %s",
        (curlx_dyn_len(&out[1]) ? curlx_dyn_ptr(&out[1]) : "(none)"));
#endif
  infof(data, "IPv4: %s",
        (curlx_dyn_len(&out[0]) ? curlx_dyn_ptr(&out[0]) : "(none)"));

fail:
  curlx_dyn_free(&out[0]);
#ifdef CURLRES_IPV6
  curlx_dyn_free(&out[1]);
#endif
}
#else
#define show_resolve_info(x, y) Curl_nop_stmt
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
static curl_simple_lock curl_jmpenv_lock;
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

  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons(port16);
  sa6.sin6_flowinfo = 0;
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
  sa6.sin6_scope_id = 0;
#endif

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
 * Curl_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Curl_ipv6works(struct Curl_easy *data)
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

static bool can_resolve_ip_version(struct Curl_easy *data, int ip_version)
{
#ifdef CURLRES_IPV6
  if(ip_version == CURL_IPRESOLVE_V6 && !Curl_ipv6works(data))
    return FALSE;
#elif defined(CURLRES_IPV4)
  (void)data;
  if(ip_version == CURL_IPRESOLVE_V6)
    return FALSE;
#else
#error either CURLRES_IPV6 or CURLRES_IPV4 need to be defined
#endif
  return TRUE;
}

#ifdef USE_CURL_ASYNC
static CURLcode hostip_async_new(struct Curl_easy *data,
                                 const char *hostname,
                                 uint16_t port,
                                 uint8_t ip_version)
{
  struct Curl_resolv_async *async;
  size_t hostlen = strlen(hostname);

  DEBUGASSERT(!data->state.async);
  /* struct size already includes the NUL for hostname */
  async = curlx_calloc(1, sizeof(*async) + hostlen);
  if(!async)
    return CURLE_OUT_OF_MEMORY;

  async->port = port;
  async->ip_version = ip_version;
  if(hostlen)
    memcpy(async->hostname, hostname, hostlen);
  async->start = *Curl_pgrs_now(data);

  data->state.async = async;
  return CURLE_OK;
}
#endif

#ifdef USE_CURL_ASYNC
static CURLcode hostip_resolv_take_result(struct Curl_easy *data,
                                          struct Curl_dns_entry **pdns)
{
  struct Curl_resolv_async *async = data->state.async;
  CURLcode result;

  /* If async resolving is ongoing, this must be set */
  if(!async)
    return CURLE_FAILED_INIT;

#ifndef CURL_DISABLE_DOH
  if(data->conn->bits.doh)
    result = Curl_doh_take_result(data, pdns);
  else
#endif
  result = Curl_async_take_result(data, async, pdns);

  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  else if(result)
    Curl_resolver_error(data, NULL);
  else
    DEBUGASSERT(*pdns);

  return result;
}
#endif

static CURLcode hostip_resolv_announce(struct Curl_easy *data,
                                       const char *hostname,
                                       uint16_t port,
                                       uint8_t ip_version)
{
  if(data->set.resolver_start) {
    void *resolver = NULL;
    int st;
#ifdef CURLRES_ASYNCH
    CURLcode result;
    if(!data->state.async) {
      result = hostip_async_new(data, hostname, port, ip_version);
      if(result)
        return result;
    }

    result = Curl_async_get_impl(data, data->state.async, &resolver);
    if(result)
      return result;
#else
    (void)hostname;
    (void)port;
    (void)ip_version;
#endif
    Curl_set_in_callback(data, TRUE);
    st = data->set.resolver_start(resolver, NULL,
                                  data->set.resolver_start_client);
    Curl_set_in_callback(data, FALSE);
    if(st) {
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }
  return CURLE_OK;
}

static CURLcode hostip_resolv_start(struct Curl_easy *data,
                                    const char *hostname,
                                    uint16_t port,
                                    uint8_t ip_version,
                                    bool allowDOH,
                                    struct Curl_dns_entry **pdns)
{
  struct Curl_addrinfo *addr = NULL;
  size_t hostname_len;
  CURLcode result = CURLE_OK;

  *pdns = NULL;

  /* really need to start a resolve operation */
  result = hostip_resolv_announce(data, hostname, port, ip_version);
  if(result)
    goto out;

  /* Check for "known" things to resolve ourselves. */
#ifndef USE_RESOLVE_ON_IPS
  if(Curl_is_ipaddr(hostname)) {
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
    addr = get_localhost(port, hostname);
    if(!addr)
      result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

#ifndef CURL_DISABLE_DOH
  if(!Curl_is_ipaddr(hostname) && allowDOH && data->set.doh) {
    if(!data->state.async) {
      result = hostip_async_new(data, hostname, port, ip_version);
      if(result)
        goto out;
    }
    result = Curl_doh(data, data->state.async);
    goto out;
  }
#else
  (void)allowDOH;
#endif

  /* Can we provide the requested IP specifics in resolving? */
  if(!can_resolve_ip_version(data, ip_version)) {
    result = CURLE_COULDNT_RESOLVE_HOST;
    goto out;
  }

#ifdef CURLRES_ASYNCH
  (void)addr;
  if(!data->state.async) {
    result = hostip_async_new(data, hostname, port, ip_version);
    if(result)
      goto out;
  }
  result = Curl_async_getaddrinfo(data, data->state.async);
  if(result == CURLE_AGAIN) {
    /* the answer might be there already. Check. */
    CURLcode r2 = hostip_resolv_take_result(data, pdns);
    if(r2)
      result = r2;
    else if(*pdns)
      result = CURLE_OK;
  }
#else
  addr = Curl_sync_getaddrinfo(data, hostname, port, ip_version);
  if(!addr)
    result = CURLE_COULDNT_RESOLVE_HOST;
#endif

out:
  if(!result) {
    if(addr) {
      /* we got a response, create a dns entry, add to cache, return */
      DEBUGASSERT(!*pdns);
      *pdns = Curl_dns_entry_create(data, &addr, hostname, port, ip_version);
      if(!*pdns)
        result = CURLE_OUT_OF_MEMORY;
    }
    else if(!*pdns)
      result = CURLE_AGAIN;

    if(*pdns)
      show_resolve_info(data, *pdns);
  }
  else if(*pdns)
    Curl_dns_entry_unlink(data, pdns);
  else if(addr)
    Curl_freeaddrinfo(addr);

  return result;
}

static CURLcode hostip_resolv(struct Curl_easy *data,
                              const char *hostname,
                              uint16_t port,
                              uint8_t ip_version,
                              bool allowDOH,
                              struct Curl_dns_entry **pdns)
{
  size_t hostname_len;
  CURLcode result = CURLE_OK;
  bool cache_dns = FALSE;

  *pdns = NULL;

#ifdef USE_CURL_ASYNC
  if(data->state.async)
    Curl_async_destroy(data);
#endif

#ifndef CURL_DISABLE_DOH
  data->conn->bits.doh = FALSE; /* default is not */
#else
  (void)allowDOH;
#endif

  /* We should intentionally error and not resolve .onion TLDs */
  hostname_len = strlen(hostname);
  DEBUGASSERT(hostname_len);
  if(hostname_len >= 7 &&
     (curl_strequal(&hostname[hostname_len - 6], ".onion") ||
      curl_strequal(&hostname[hostname_len - 7], ".onion."))) {
    failf(data, "Not resolving .onion address (RFC 7686)");
    result = CURLE_COULDNT_RESOLVE_HOST;
    goto out;
  }

#ifdef DEBUGBUILD
  if((ip_version == CURL_IPRESOLVE_V6) &&
     getenv("CURL_DBG_RESOLV_FAIL_IPV6")) {
    infof(data, "DEBUG fail ipv6 resolve");
    result = Curl_resolver_error(data, NULL);
    goto out;
  }
#endif

  /* Let's check our DNS cache next */
  result = Curl_dnscache_get(data, hostname, port, ip_version, pdns);
  if(*pdns) {
    infof(data, "Hostname %s was found in DNS cache", hostname);
  }
  else if(result) {
    DEBUGASSERT(!*pdns);
    infof(data, "Negative DNS entry");
    result = Curl_resolver_error(data, NULL);
  }
  else {
    /* No luck, we need to start resolving. */
    cache_dns = TRUE;
    result = hostip_resolv_start(data, hostname, port, ip_version,
                                 allowDOH, pdns);
  }

out:
  if(result && (result != CURLE_AGAIN)) {
    Curl_dns_entry_unlink(data, pdns);
    Curl_async_shutdown(data);
    if((result == CURLE_COULDNT_RESOLVE_HOST) ||
       (result == CURLE_COULDNT_RESOLVE_PROXY)) {
      if(cache_dns)
        Curl_dnscache_add_negative(data, hostname, port, ip_version);
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
    else
      show_resolve_info(data, *pdns);
  }

  CURL_TRC_DNS(data, "hostip_resolv(%s:%u, ip=%x) -> %d, dns %sfound",
               hostname, port, ip_version, result,
               *pdns ? "" : "not ");
  return result;
}

CURLcode Curl_resolv_blocking(struct Curl_easy *data,
                              const char *hostname,
                              uint16_t port,
                              uint8_t ip_version,
                              struct Curl_dns_entry **pdns)
{
  CURLcode result;
  DEBUGASSERT(hostname && *hostname);
  *pdns = NULL;
  /* We cannot do a blocking resolve using DoH currently */
  result = hostip_resolv(data, hostname, port, ip_version, FALSE, pdns);
  switch(result) {
  case CURLE_OK:
    DEBUGASSERT(*pdns);
    return CURLE_OK;
#ifdef USE_CURL_ASYNC
  case CURLE_AGAIN:
    DEBUGASSERT(!*pdns);
    if(!data->state.async)
      return CURLE_FAILED_INIT;
    return Curl_async_await(data, data->state.async, pdns);
#endif
  default:
    return result;
  }
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
                                     const char *hostname,
                                     uint16_t port,
                                     uint8_t ip_version,
                                     timediff_t timeoutms,
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
  DEBUGASSERT(timeoutms > 0);
  DEBUGASSERT(data->set.no_signal);
#ifndef CURL_DISABLE_DOH
  DEBUGASSERT(!data->set.doh);
#endif

  *entry = NULL;
  timeout = (timeoutms > LONG_MAX) ? LONG_MAX : (long)timeoutms;
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
  result = hostip_resolv(data, hostname, port, ip_version, TRUE, entry);

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
 * CURLE_OK = success, *entry set to non-NULL
 * CURLE_AGAIN = resolving in progress, *entry == NULL
 * CURLE_COULDNT_RESOLVE_HOST = error, *entry == NULL
 * CURLE_OPERATION_TIMEDOUT = timeout expired, *entry == NULL
 */
CURLcode Curl_resolv(struct Curl_easy *data,
                     const char *hostname,
                     uint16_t port,
                     uint8_t ip_version,
                     timediff_t timeoutms,
                     struct Curl_dns_entry **entry)
{
  DEBUGASSERT(hostname && *hostname);
  *entry = NULL;

  if(timeoutms < 0)
    /* got an already expired timeout */
    return CURLE_OPERATION_TIMEDOUT;

#ifdef USE_ALARM_TIMEOUT
  if(timeoutms && !data->set.no_signal) {
    /* Cannot use ALARM when signals are disabled */
    timeoutms = 0;
  }
  if(timeoutms && !Curl_doh_wanted(data)) {
    return resolv_alarm_timeout(data, hostname, port, ip_version,
                                timeoutms, entry);
  }
#endif /* !USE_ALARM_TIMEOUT */

#ifndef CURLRES_ASYNCH
  if(timeoutms)
    infof(data, "timeout on name lookup is not supported");
#endif

  return hostip_resolv(data, hostname, port, ip_version, TRUE, entry);
}


#ifdef USE_CURL_ASYNC
CURLcode Curl_resolv_take_result(struct Curl_easy *data,
                                 struct Curl_dns_entry **pdns)
{
  struct Curl_resolv_async *async = data->state.async;
  CURLcode result;

  if(!async) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }

  /* check if we have the name resolved by now (from someone else) */
  result = Curl_dnscache_get(data, async->hostname, async->port,
                             async->ip_version, pdns);
  if(*pdns) {
    /* Tell a possibly async resolver we no longer need the results. */
    infof(data, "Hostname '%s' was found in DNS cache", async->hostname);
    Curl_async_shutdown(data);
    return CURLE_OK;
  }
  else if(result) {
    Curl_async_shutdown(data);
    return Curl_resolver_error(data, NULL);
  }

  result = hostip_resolv_take_result(data, pdns);

  if(*pdns) {
    /* Add to cache */
    result = Curl_dnscache_add(data, *pdns);
    if(result)
      Curl_dns_entry_unlink(data, pdns);
    else
      show_resolve_info(data, *pdns);
  }
  else if((result == CURLE_COULDNT_RESOLVE_HOST) ||
          (result == CURLE_COULDNT_RESOLVE_PROXY)) {
    Curl_dnscache_add_negative(data, async->hostname,
                               async->port, async->ip_version);
    failf(data, "Could not resolve: %s:%u", async->hostname, async->port);
  }
  else if(result) {
    failf(data, "Error %d resolving %s:%u",
          result, async->hostname, async->port);
  }
  return result;
}
#endif

CURLcode Curl_resolv_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps)
{
#ifdef CURLRES_ASYNCH
#ifndef CURL_DISABLE_DOH
  if(data->conn->bits.doh)
    /* nothing to wait for during DoH resolve, those handles have their own
       sockets */
    return CURLE_OK;
#endif
  return Curl_async_pollset(data, ps);
#else
  (void)data;
  (void)ps;
  return CURLE_OK;
#endif
}

/*
 * Curl_resolver_error() calls failf() with the appropriate message after a
 * resolve error
 */

#ifdef USE_CURL_ASYNC
CURLcode Curl_resolver_error(struct Curl_easy *data, const char *detail)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_COULDNT_RESOLVE_HOST;
  VERBOSE(const char *host_or_proxy = "host");
  VERBOSE(const char *name = conn->host.dispname);

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.proxy) {
    result = CURLE_COULDNT_RESOLVE_PROXY;
    VERBOSE(host_or_proxy = "proxy");
    VERBOSE(name = conn->socks_proxy.host.name ?
      conn->socks_proxy.host.dispname : conn->http_proxy.host.dispname);
  }
#endif

  if(detail)
    infof(data, "error resolving %s: %s (%s)", host_or_proxy, name, detail);
  return result;
}
#endif /* USE_CURL_ASYNC */
