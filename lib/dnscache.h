#ifndef HEADER_CURL_DNSCACHE_H
#define HEADER_CURL_DNSCACHE_H
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

struct addrinfo;
struct hostent;
struct Curl_easy;
struct connectdata;
struct easy_pollset;
struct Curl_https_rrinfo;
struct Curl_multi;

struct Curl_dns_entry {
  struct Curl_addrinfo *addr;
#ifdef USE_HTTPSRR
  struct Curl_https_rrinfo *hinfo;
#endif
  /* timestamp == 0 -- permanent CURLOPT_RESOLVE entry (does not time out) */
  struct curltime timestamp;
  /* reference counter, entry is freed on reaching 0 */
  uint32_t refcount;
  /* hostname port number that resolved to addr. */
  uint16_t port;
  uint8_t ip_version;
  /* hostname that resolved to addr. may be NULL (Unix domain sockets). */
  char hostname[1];
};

/*
 * Create a `Curl_dns_entry` with a reference count of 1.
 * Use `Curl_dns_entry_unlink()` to release your hold on it.
 *
 * The call takes ownership of `addr`, even in case of failure, and always
 * clears `*paddr`. It makes a copy of `hostname`.
 *
 * Returns entry or NULL on OOM.
 */
struct Curl_dns_entry *
Curl_dns_entry_create(struct Curl_easy *data,
                      struct Curl_addrinfo **paddr,
                      const char *hostname,
                      uint16_t port, uint8_t ip_version);

/* unlink a dns entry, frees all resources if it was the last reference.
 * Always clears `*pdns`` */
void Curl_dns_entry_unlink(struct Curl_easy *data,
                           struct Curl_dns_entry **pdns);


struct Curl_dnscache {
  struct Curl_hash entries;
};

/* init a new dns cache */
void Curl_dnscache_init(struct Curl_dnscache *dns, size_t hashsize);

void Curl_dnscache_destroy(struct Curl_dnscache *dns);

/* prune old entries from the DNS cache */
void Curl_dnscache_prune(struct Curl_easy *data);

/* clear the DNS cache */
void Curl_dnscache_clear(struct Curl_easy *data);

/*
 * Curl_dnscache_get() fetches a 'Curl_dns_entry' already in the DNS cache.
 *
 * Returns the Curl_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Curl_dns_entry_unlink() after
 * use, or we will leak memory!
 * Returns CURLE_OK or CURLE_COULDNT_RESOLVE_HOST when a negative
 * entry was in the cache.
 */
CURLcode Curl_dnscache_get(struct Curl_easy *data,
                           const char *hostname,
                           uint16_t port,
                           uint8_t ip_version,
                           struct Curl_dns_entry **pentry);

/*
 * Curl_dnscache_addr() adds `entry` to the cache, increasing its
 * reference count on success.
 */
CURLcode Curl_dnscache_add(struct Curl_easy *data,
                           struct Curl_dns_entry *entry);

/* Store a "negative" entry for host:port, e.g. remember that
 * it could not be resolved. */
CURLcode Curl_dnscache_add_negative(struct Curl_easy *data,
                                    const char *host,
                                    uint16_t port,
                                    uint8_t ip_version);

/*
 * Populate the cache with specified entries from CURLOPT_RESOLVE.
 */
CURLcode Curl_loadhostpairs(struct Curl_easy *data);

#endif /* HEADER_CURL_DNSCACHE_H */
