#ifndef HEADER_FETCH_HOSTIP_H
#define HEADER_FETCH_HOSTIP_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"
#include "hash.h"
#include "fetch_addrinfo.h"
#include "timeval.h" /* for timediff_t */
#include "asyn.h"
#include "httpsrr.h"

#include <setjmp.h>

#ifdef USE_HTTPSRR
#include <stdint.h>
#endif

/* Allocate enough memory to hold the full name information structs and
 * everything. OSF1 is known to require at least 8872 bytes. The buffer
 * required for storing all possible aliases and IP numbers is according to
 * Stevens' Unix Network Programming 2nd edition, p. 304: 8192 bytes!
 */
#define FETCH_HOSTENT_SIZE 9000

#define FETCH_TIMEOUT_RESOLVE 300 /* when using asynch methods, we allow this \
                                    many seconds for a name resolve */

#define FETCH_ASYNC_SUCCESS FETCHE_OK

struct addrinfo;
struct hostent;
struct Fetch_easy;
struct connectdata;

enum alpnid
{
  ALPN_none = 0,
  ALPN_h1 = FETCHALTSVC_H1,
  ALPN_h2 = FETCHALTSVC_H2,
  ALPN_h3 = FETCHALTSVC_H3
};

/*
 * Fetch_global_host_cache_init() initializes and sets up a global DNS cache.
 * Global DNS cache is general badness. Do not use. This will be removed in
 * a future version. Use the share interface instead!
 *
 * Returns a struct Fetch_hash pointer on success, NULL on failure.
 */
struct Fetch_hash *Fetch_global_host_cache_init(void);

struct Fetch_dns_entry
{
  struct Fetch_addrinfo *addr;
#ifdef USE_HTTPSRR
  struct Fetch_https_rrinfo *hinfo;
#endif
  /* timestamp == 0 -- permanent FETCHOPT_RESOLVE entry (does not time out) */
  time_t timestamp;
  /* reference counter, entry is freed on reaching 0 */
  size_t refcount;
  /* hostname port number that resolved to addr. */
  int hostport;
  /* hostname that resolved to addr. may be NULL (Unix domain sockets). */
  char hostname[1];
};

bool Fetch_host_is_ipnum(const char *hostname);

/*
 * Fetch_resolv() returns an entry with the info for the specified host
 * and port.
 *
 * The returned data *MUST* be "released" with Fetch_resolv_unlink() after
 * use, or we will leak memory!
 */
/* return codes */
enum resolve_t
{
  FETCHRESOLV_TIMEDOUT = -2,
  FETCHRESOLV_ERROR = -1,
  FETCHRESOLV_RESOLVED = 0,
  FETCHRESOLV_PENDING = 1
};
enum resolve_t Fetch_resolv(struct Fetch_easy *data,
                           const char *hostname,
                           int port,
                           bool allowDOH,
                           struct Fetch_dns_entry **dnsentry);
enum resolve_t Fetch_resolv_timeout(struct Fetch_easy *data,
                                   const char *hostname, int port,
                                   struct Fetch_dns_entry **dnsentry,
                                   timediff_t timeoutms);

#ifdef USE_IPV6
/*
 * Fetch_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Fetch_ipv6works(struct Fetch_easy *data);
#else
#define Fetch_ipv6works(x) FALSE
#endif

/*
 * Fetch_ipvalid() checks what FETCH_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Fetch_ipvalid(struct Fetch_easy *data, struct connectdata *conn);

/*
 * Fetch_getaddrinfo() is the generic low-level name resolve API within this
 * source file. There are several versions of this function - for different
 * name resolve layers (selected at build-time). They all take this same set
 * of arguments
 */
struct Fetch_addrinfo *Fetch_getaddrinfo(struct Fetch_easy *data,
                                       const char *hostname,
                                       int port,
                                       int *waitp);

/* unlink a dns entry, potentially shared with a cache */
void Fetch_resolv_unlink(struct Fetch_easy *data,
                        struct Fetch_dns_entry **pdns);

/* init a new dns cache */
void Fetch_init_dnscache(struct Fetch_hash *hash, size_t hashsize);

/* prune old entries from the DNS cache */
void Fetch_hostcache_prune(struct Fetch_easy *data);

/* IPv4 threadsafe resolve function used for synch and asynch builds */
struct Fetch_addrinfo *Fetch_ipv4_resolve_r(const char *hostname, int port);

FETCHcode Fetch_once_resolved(struct Fetch_easy *data, bool *protocol_connect);

/*
 * Fetch_addrinfo_callback() is used when we build with any asynch specialty.
 * Handles end of async request processing. Inserts ai into hostcache when
 * status is FETCH_ASYNC_SUCCESS. Twiddles fields in conn to indicate async
 * request completed whether successful or failed.
 */
FETCHcode Fetch_addrinfo_callback(struct Fetch_easy *data,
                                 int status,
                                 struct Fetch_addrinfo *ai);

/*
 * Fetch_printable_address() returns a printable version of the 1st address
 * given in the 'ip' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 */
void Fetch_printable_address(const struct Fetch_addrinfo *ip,
                            char *buf, size_t bufsize);

/*
 * Fetch_fetch_addr() fetches a 'Fetch_dns_entry' already in the DNS cache.
 *
 * Returns the Fetch_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Fetch_resolv_unlink() after
 * use, or we will leak memory!
 */
struct Fetch_dns_entry *
Fetch_fetch_addr(struct Fetch_easy *data,
                const char *hostname,
                int port);

/*
 * Fetch_cache_addr() stores a 'Fetch_addrinfo' struct in the DNS cache.
 * @param permanent   iff TRUE, entry will never become stale
 * Returns the Fetch_dns_entry entry pointer or NULL if the storage failed.
 */
struct Fetch_dns_entry *
Fetch_cache_addr(struct Fetch_easy *data, struct Fetch_addrinfo *addr,
                const char *hostname, size_t hostlen, int port,
                bool permanent);

#ifndef INADDR_NONE
#define FETCH_INADDR_NONE (in_addr_t) ~0
#else
#define FETCH_INADDR_NONE INADDR_NONE
#endif

/*
 * Function provided by the resolver backend to set DNS servers to use.
 */
FETCHcode Fetch_set_dns_servers(struct Fetch_easy *data, char *servers);

/*
 * Function provided by the resolver backend to set
 * outgoing interface to use for DNS requests
 */
FETCHcode Fetch_set_dns_interface(struct Fetch_easy *data,
                                 const char *interf);

/*
 * Function provided by the resolver backend to set
 * local IPv4 address to use as source address for DNS requests
 */
FETCHcode Fetch_set_dns_local_ip4(struct Fetch_easy *data,
                                 const char *local_ip4);

/*
 * Function provided by the resolver backend to set
 * local IPv6 address to use as source address for DNS requests
 */
FETCHcode Fetch_set_dns_local_ip6(struct Fetch_easy *data,
                                 const char *local_ip6);

/*
 * Clean off entries from the cache
 */
void Fetch_hostcache_clean(struct Fetch_easy *data, struct Fetch_hash *hash);

/*
 * Populate the cache with specified entries from FETCHOPT_RESOLVE.
 */
FETCHcode Fetch_loadhostpairs(struct Fetch_easy *data);
FETCHcode Fetch_resolv_check(struct Fetch_easy *data,
                            struct Fetch_dns_entry **dns);
int Fetch_resolv_getsock(struct Fetch_easy *data,
                        fetch_socket_t *socks);

FETCHcode Fetch_resolver_error(struct Fetch_easy *data);
#endif /* HEADER_FETCH_HOSTIP_H */
