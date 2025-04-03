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
#include "timeval.h" /* for timediff_t */
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

#define CURL_ASYNC_SUCCESS CURLE_OK

struct addrinfo;
struct hostent;
struct Curl_easy;
struct connectdata;

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
  time_t timestamp;
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
/* return codes */
enum resolve_t {
  CURLRESOLV_TIMEDOUT = -2,
  CURLRESOLV_ERROR    = -1,
  CURLRESOLV_RESOLVED =  0,
  CURLRESOLV_PENDING  =  1
};
enum resolve_t Curl_resolv(struct Curl_easy *data,
                           const char *hostname,
                           int port,
                           bool allowDOH,
                           struct Curl_dns_entry **dnsentry);
enum resolve_t Curl_resolv_timeout(struct Curl_easy *data,
                                   const char *hostname, int port,
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

/*
 * Curl_ipvalid() checks what CURL_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Curl_ipvalid(struct Curl_easy *data, struct connectdata *conn);


/*
 * Curl_getaddrinfo() is the generic low-level name resolve API within this
 * source file. There are several versions of this function - for different
 * name resolve layers (selected at build-time). They all take this same set
 * of arguments
 */
struct Curl_addrinfo *Curl_getaddrinfo(struct Curl_easy *data,
                                       const char *hostname,
                                       int port,
                                       int *waitp);


/* unlink a dns entry, potentially shared with a cache */
void Curl_resolv_unlink(struct Curl_easy *data,
                        struct Curl_dns_entry **pdns);

/* init a new dns cache */
void Curl_dnscache_init(struct Curl_dnscache *dns, size_t hashsize);

void Curl_dnscache_destroy(struct Curl_dnscache *dns);

/* prune old entries from the DNS cache */
void Curl_dnscache_prune(struct Curl_easy *data);

/* IPv4 threadsafe resolve function used for synch and asynch builds */
struct Curl_addrinfo *Curl_ipv4_resolve_r(const char *hostname, int port);

CURLcode Curl_once_resolved(struct Curl_easy *data, bool *protocol_connect);

/*
 * Curl_addrinfo_callback() is used when we build with any asynch specialty.
 * Handles end of async request processing. Inserts ai into dnscache when
 * status is CURL_ASYNC_SUCCESS. Twiddles fields in conn to indicate async
 * request completed whether successful or failed.
 */
CURLcode Curl_addrinfo_callback(struct Curl_easy *data,
                                int status,
                                struct Curl_addrinfo *ai);

/*
 * Curl_printable_address() returns a printable version of the 1st address
 * given in the 'ip' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 */
void Curl_printable_address(const struct Curl_addrinfo *ip,
                            char *buf, size_t bufsize);

/*
 * Curl_fetch_addr() fetches a 'Curl_dns_entry' already in the DNS cache.
 *
 * Returns the Curl_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Curl_resolv_unlink() after
 * use, or we will leak memory!
 */
struct Curl_dns_entry *
Curl_fetch_addr(struct Curl_easy *data,
                const char *hostname,
                int port);

/*
 * Curl_cache_addr() stores a 'Curl_addrinfo' struct in the DNS cache.
 * Call takes ownership of `addr` and free's it on failure.
 * @param permanent   iff TRUE, entry will never become stale
 * Returns the Curl_dns_entry entry pointer or NULL if the storage failed.
 */
struct Curl_dns_entry *
Curl_cache_addr(struct Curl_easy *data, struct Curl_addrinfo *addr,
                const char *hostname, size_t hostlen, int port,
                bool permanent);

/*
 * Function provided by the resolver backend to set DNS servers to use.
 */
CURLcode Curl_set_dns_servers(struct Curl_easy *data, char *servers);

/*
 * Function provided by the resolver backend to set
 * outgoing interface to use for DNS requests
 */
CURLcode Curl_set_dns_interface(struct Curl_easy *data,
                                const char *interf);

/*
 * Function provided by the resolver backend to set
 * local IPv4 address to use as source address for DNS requests
 */
CURLcode Curl_set_dns_local_ip4(struct Curl_easy *data,
                                const char *local_ip4);

/*
 * Function provided by the resolver backend to set
 * local IPv6 address to use as source address for DNS requests
 */
CURLcode Curl_set_dns_local_ip6(struct Curl_easy *data,
                                const char *local_ip6);

/*
 * Populate the cache with specified entries from CURLOPT_RESOLVE.
 */
CURLcode Curl_loadhostpairs(struct Curl_easy *data);
CURLcode Curl_resolv_check(struct Curl_easy *data,
                           struct Curl_dns_entry **dns);
int Curl_resolv_getsock(struct Curl_easy *data,
                        curl_socket_t *socks);

CURLcode Curl_resolver_error(struct Curl_easy *data);
#endif /* HEADER_CURL_HOSTIP_H */
