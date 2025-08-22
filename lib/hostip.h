#ifndef HEADER_CURL_HOSTIP_H
#define HEADER_CURL_HOSTIP_H
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
#include "hash.h"
#include "curl_addrinfo.h"
#include "curlx/timeval.h" /* for timediff_t */
#include "asyn.h"
#include "httpsrr.h"

#include <setjmp.h>

#ifdef USE_HTTPSRR
# include <stdint.h>
#endif

/* Allocate enough memory to hold the full name information structs and
 * everything. OSF1 is known to require at least 8872 bytes. The buffer
 * required for storing all possible aliases and IP numbers is according to
 * Stevens' Unix Network Programming 2nd edition, p. 304: 8192 bytes!
 */
#define CURL_HOSTENT_SIZE 9000

#define CURL_TIMEOUT_RESOLVE 300 /* when using asynch methods, we allow this
                                    many seconds for a name resolve */

struct addrinfo;
struct hostent;
struct Curl_easy;
struct connectdata;
struct easy_pollset;

enum alpnid {
  ALPN_none = 0,
  ALPN_h1 = CURLALTSVC_H1,
  ALPN_h2 = CURLALTSVC_H2,
  ALPN_h3 = CURLALTSVC_H3
};

struct Curl_dns_entry {
  struct Curl_addrinfo *addr;
#ifdef USE_HTTPSRR
  struct Curl_https_rrinfo *hinfo;
#endif
  /* timestamp == 0 -- permanent CURLOPT_RESOLVE entry (does not time out) */
  struct curltime timestamp;
  /* reference counter, entry is freed on reaching 0 */
  size_t refcount;
  /* hostname port number that resolved to addr. */
  int hostport;
  /* hostname that resolved to addr. may be NULL (Unix domain sockets). */
  char hostname[1];
};

struct Curl_dnscache {
  struct Curl_hash entries;
};

bool Curl_host_is_ipnum(const char *hostname);

/*
 * Curl_resolv() returns an entry with the info for the specified host
 * and port.
 *
 * The returned data *MUST* be "released" with Curl_resolv_unlink() after
 * use, or we will leak memory!
 */
CURLcode Curl_resolv(struct Curl_easy *data,
                     const char *hostname,
                     int port,
                     int ip_version,
                     bool allowDOH,
                     struct Curl_dns_entry **dnsentry);

CURLcode Curl_resolv_blocking(struct Curl_easy *data,
                              const char *hostname,
                              int port,
                              int ip_version,
                              struct Curl_dns_entry **dnsentry);

CURLcode Curl_resolv_timeout(struct Curl_easy *data,
                             const char *hostname, int port,
                             int ip_version,
                             struct Curl_dns_entry **dnsentry,
                             timediff_t timeoutms);

#ifdef USE_IPV6
/*
 * Curl_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Curl_ipv6works(struct Curl_easy *data);
#else
#define Curl_ipv6works(x) FALSE
#endif


/* unlink a dns entry, potentially shared with a cache */
void Curl_resolv_unlink(struct Curl_easy *data,
                        struct Curl_dns_entry **pdns);

/* init a new dns cache */
void Curl_dnscache_init(struct Curl_dnscache *dns, size_t hashsize);

void Curl_dnscache_destroy(struct Curl_dnscache *dns);

/* prune old entries from the DNS cache */
void Curl_dnscache_prune(struct Curl_easy *data);

/* clear the DNS cache */
void Curl_dnscache_clear(struct Curl_easy *data);

/* IPv4 threadsafe resolve function used for synch and asynch builds */
struct Curl_addrinfo *Curl_ipv4_resolve_r(const char *hostname, int port);

CURLcode Curl_once_resolved(struct Curl_easy *data,
                            struct Curl_dns_entry *dns,
                            bool *protocol_connect);

/*
 * Curl_printable_address() returns a printable version of the 1st address
 * given in the 'ip' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 */
void Curl_printable_address(const struct Curl_addrinfo *ip,
                            char *buf, size_t bufsize);

/*
 * Make a `Curl_dns_entry`.
 * Creates a dnscache entry *without* adding it to a dnscache. This allows
 * further modifications of the entry *before* then adding it to a cache.
 *
 * The entry is created with a reference count of 1.
 * Use `Curl_resolv_unlink()` to release your hold on it.
 *
 * The call takes ownership of `addr`and makes a copy of `hostname`.
 *
 * Returns entry or NULL on OOM.
 */
struct Curl_dns_entry *
Curl_dnscache_mk_entry(struct Curl_easy *data,
                       struct Curl_addrinfo *addr,
                       const char *hostname,
                       size_t hostlen, /* length or zero */
                       int port,
                       bool permanent);

/*
 * Curl_dnscache_get() fetches a 'Curl_dns_entry' already in the DNS cache.
 *
 * Returns the Curl_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Curl_resolv_unlink() after
 * use, or we will leak memory!
 */
struct Curl_dns_entry *
Curl_dnscache_get(struct Curl_easy *data,
                  const char *hostname,
                  int port, int ip_version);

/*
 * Curl_dnscache_addr() adds `entry` to the cache, increasing its
 * reference count on success.
 */
CURLcode Curl_dnscache_add(struct Curl_easy *data,
                           struct Curl_dns_entry *entry);

/*
 * Populate the cache with specified entries from CURLOPT_RESOLVE.
 */
CURLcode Curl_loadhostpairs(struct Curl_easy *data);

#ifdef USE_CURL_ASYNC
CURLcode Curl_resolv_check(struct Curl_easy *data,
                           struct Curl_dns_entry **dns);
#else
#define Curl_resolv_check(x,y) CURLE_NOT_BUILT_IN
#endif
CURLcode Curl_resolv_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps);

CURLcode Curl_resolver_error(struct Curl_easy *data, const char *detail);

#ifdef CURLRES_SYNCH
/*
 * Curl_sync_getaddrinfo() is the non-async low-level name resolve API.
 * There are several versions of this function - depending on IPV6
 * support and platform.
 */
struct Curl_addrinfo *Curl_sync_getaddrinfo(struct Curl_easy *data,
                                            const char *hostname,
                                            int port,
                                            int ip_version);

#endif

#ifdef DEBUGBUILD
void Curl_resolve_test_delay(void);
#endif

#endif /* HEADER_CURL_HOSTIP_H */
