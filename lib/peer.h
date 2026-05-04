#ifndef HEADER_CURL_AUTHORITY_H
#define HEADER_CURL_AUTHORITY_H
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

struct Curl_scheme;
struct urlpieces;

/* if peer hostname starts with this, the peer is a unix domain socket
 * path, e.g. the remainder after 'localhost'. */
#define CURL_PEER_UDS_PREFIX "localhost/"

struct Curl_peer {
  const struct Curl_scheme *scheme; /* url scheme */
  char *hostname; /* normalized hostname (IDN decoded when supported) */
  char *user_ipv6zone; /* NULL or ipv6 zone identifier used */
  uint32_t refcount;  /* created with 1, freed when dropping to 0 */
  uint32_t ipv6scope_id; /* != 0, ipv6 scope to use */
  uint16_t port;
  BIT(unix_socket); /* hostname is a UDS path without the prefix */
  BIT(abstract); /* only TRUE when `unix_socket` also TRUE */
  BIT(ipv6); /* hostname is an IPv6 address stripped of '[]' */
  char user_hostname[1]; /* hostname supplied by user/url */
};

/* Create a new peer:
 * - `peer->user_hostname` is the passed `hostname`
 * - `peer->hostname` is the normalized `hostname` via
 *    + IDN conversion if it has non-ASCII characters
 *    + stripping of surrounding '[]' for URL formatted ipv6 addresses
 *    + the path alone in case of a unix domain socket, e.g. hostname
 *      starts with CURL_PEER_UDS_PREFIX and is longer
 * - `ipv6zone` may be NULL or is translated to `ipv6scope_id` unless
 *   `ipv6scope_id` is not 0 already.
 * - `ipv6scope_id`, 0 or ipv6 scope id
 */
CURLcode Curl_peer_create(const struct Curl_scheme *scheme,
                          const char *hostname, size_t hostlen,
                          uint16_t port,
                          const char *ipv6zone,
                          uint32_t ipv6scope_id,
                          struct Curl_peer **ppeer);

#ifdef USE_UNIX_SOCKETS
CURLcode Curl_peer_uds_create(const struct Curl_scheme *scheme,
                              const char *path,
                              bool abstract_unix_socket,
                              struct Curl_peer **ppeer);
#endif

/* Unlink any peer in `*pdest`, assign src, increase src
 * refcount when not NULL. */
void Curl_peer_link(struct Curl_peer **pdest, struct Curl_peer *src);

/* Drop a reference, peer may be passed as NULL */
void Curl_peer_unlink(struct Curl_peer **ppeer);

/* TRUE if both peers are NULL or have completely same properties. */
bool Curl_peer_equal(struct Curl_peer *p1, struct Curl_peer *p2);

/* TRUE if both peers are NULL or have properties except the scheme. */
bool Curl_peer_same_destination(struct Curl_peer *p1, struct Curl_peer *p2);

CURLcode Curl_peer_from_url(CURLU *uh, struct Curl_easy *data,
                            uint16_t port_override,
                            uint32_t ipv6scopeid_override,
                            struct urlpieces *up,
                            struct Curl_peer **ppeer);

#ifndef CURL_DISABLE_PROXY

CURLcode Curl_peer_from_proxy_url(CURLU *uh,
                                  struct Curl_easy *data,
                                  const char *url,
                                  uint8_t proxytype,
                                  struct Curl_peer **ppeer,
                                  uint8_t *pproxytype);
#endif /* !CURL_DISABLE_PROXY */

#endif /* HEADER_CURL_AUTHORITY_H */
