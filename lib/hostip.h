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
#include "curlx/timeval.h" /* for curltime, timediff_t */

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
struct Curl_https_rrinfo;
struct Curl_multi;
struct Curl_dns_entry;

enum alpnid {
  ALPN_none = 0,
  ALPN_h1 = CURLALTSVC_H1,
  ALPN_h2 = CURLALTSVC_H2,
  ALPN_h3 = CURLALTSVC_H3
};

bool Curl_host_is_ipnum(const char *hostname);

#ifdef USE_IPV6

/* probe if it seems to work */
CURLcode Curl_probeipv6(struct Curl_multi *multi);
/*
 * Curl_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Curl_ipv6works(struct Curl_easy *data);
#else
#define Curl_probeipv6(x) CURLE_OK
#define Curl_ipv6works(x) FALSE
#endif

/* IPv4 thread-safe resolve function used for synch and asynch builds */
struct Curl_addrinfo *Curl_ipv4_resolve_r(const char *hostname, uint16_t port);

/*
 * Curl_printable_address() returns a printable version of the 1st address
 * given in the 'ip' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 */
void Curl_printable_address(const struct Curl_addrinfo *ip,
                            char *buf, size_t bufsize);

CURLcode Curl_resolv_blocking(struct Curl_easy *data,
                              const char *hostname,
                              uint16_t port,
                              uint8_t ip_version,
                              uint8_t transport,
                              struct Curl_dns_entry **dnsentry);

CURLcode Curl_resolv(struct Curl_easy *data,
                     const char *hostname,
                     uint16_t port,
                     uint8_t ip_version,
                     uint8_t transport,
                     timediff_t timeout_ms,
                     struct Curl_dns_entry **dnsentry);

#ifdef USE_CURL_ASYNC
CURLcode Curl_resolv_take_result(struct Curl_easy *data,
                                 struct Curl_dns_entry **dns);
#else
#define Curl_resolv_take_result(x, y) CURLE_NOT_BUILT_IN
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
                                            uint16_t port,
                                            uint8_t ip_version,
                                            uint8_t transport);

#endif

#ifdef USE_UNIX_SOCKETS
CURLcode Curl_resolv_unix(struct Curl_easy *data,
                          const char *unix_path,
                          bool abstract_path,
                          struct Curl_dns_entry **pdns);
#endif

#endif /* HEADER_CURL_HOSTIP_H */
