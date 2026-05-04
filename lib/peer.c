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
/*
 * IDN conversions
 */
#include "curl_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_IPHLPAPI_H
#include <Iphlpapi.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#if defined(HAVE_IF_NAMETOINDEX) && defined(USE_WINSOCK)
#if defined(__MINGW32__) && (__MINGW64_VERSION_MAJOR <= 5)
#include <wincrypt.h>  /* workaround for old mingw-w64 missing to include it */
#endif
#include <iphlpapi.h>
#endif

#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "protocol.h"
#include "http_proxy.h"
#include "idn.h"
#include "curlx/strdup.h"
#include "curlx/strparse.h"
#include "peer.h"
#include "urldata.h"
#include "url.h"
#include "vtls/vtls.h"


CURLcode Curl_peer_create(const struct Curl_scheme *scheme,
                          const char *hostname, size_t hostlen,
                          uint16_t port,
                          const char *ipv6zone,
                          uint32_t ipv6scope_id,
                          struct Curl_peer **ppeer)
{
  static const size_t puds_len = (sizeof(CURL_PEER_UDS_PREFIX) - 1);
  struct Curl_peer *peer = NULL;
  char *dns_hostname = NULL;
  CURLcode result = CURLE_OK;
  bool is_ipv6 = FALSE;
  size_t zone_len = ipv6zone ? strlen(ipv6zone) : 0;
  size_t zone_alen = zone_len ? (zone_len + 1) : 0;

  *ppeer = NULL;
  if(!scheme)
    return CURLE_FAILED_INIT;
  if(!hostlen && !(scheme->flags & PROTOPT_NONETWORK))
    return CURLE_FAILED_INIT;

  if(hostname && hostname[0] == '[') {
    /* Looks like an ipv6 url hostname */
    if((hostlen <= 2) || hostname[hostlen-1] != ']')
      return CURLE_URL_MALFORMAT;
    dns_hostname = curlx_memdup0(hostname + 1, hostlen - 2);
    if(!dns_hostname) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    /* We *could* check IPv6 address syntax, but refrain here.
     * Let address errors be detected by the layer actually making
     * the connection which knows best.
     * We also do not detect IPv6 without '[]' in URLs...let's not
     * be too smart here. */
    is_ipv6 = TRUE;
  }

  /* NUL terminator already part of struct */
  peer = curlx_calloc(1, sizeof(*peer) + hostlen + zone_alen);
  if(!peer) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  peer->refcount = 1;
  peer->scheme = scheme;
  peer->port = port;
  peer->ipv6 = is_ipv6;
  peer->unix_socket = FALSE;
  peer->ipv6scope_id = ipv6scope_id;
  if(hostlen)
    memcpy(peer->user_hostname, hostname, hostlen);
  if(zone_len) {
    peer->user_ipv6zone = peer->user_hostname + hostlen + 1;
    memcpy(peer->user_ipv6zone, ipv6zone, zone_len);
#ifdef USE_IPV6
    /* Determine scope_id if not already provided */
    if(!peer->ipv6scope_id) {
      const char *p = peer->user_ipv6zone;
      curl_off_t scope;
      if(!curlx_str_number(&p, &scope, UINT_MAX)) {
        /* A plain number, use it directly as a scope id. */
        peer->ipv6scope_id = (uint32_t)scope;
      }
#ifdef HAVE_IF_NAMETOINDEX
      else {
        /* Zone identifier is not numeric */
        unsigned int scopeidx = 0;
        scopeidx = if_nametoindex(peer->user_ipv6zone);
        if(scopeidx) {
          peer->ipv6scope_id = (uint32_t)scopeidx;
        }
        else {
          /* Do we want to return an error here? */
        }
      }
#endif /* HAVE_IF_NAMETOINDEX */
    }
#endif /* USE_IPV6 */
  }

  /* Is it a unix domain socket path? */
  if(!dns_hostname && (hostlen > puds_len) &&
     !strncmp(CURL_PEER_UDS_PREFIX, peer->user_hostname, puds_len)) {
    dns_hostname = curlx_memdup0(peer->user_hostname + puds_len - 1,
                                 hostlen - puds_len + 1);
    if(!dns_hostname) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    peer->unix_socket = TRUE;
  }
#ifdef USE_IDN
  if(!dns_hostname && !Curl_is_ASCII_name(peer->user_hostname)) {
    result = Curl_idn_decode(peer->user_hostname, &dns_hostname);
    if(result)
      goto out;
  }
#endif

  if(dns_hostname) {
    peer->hostname = dns_hostname;
    dns_hostname = NULL;
  }
  else
    peer->hostname = peer->user_hostname;

out:
  curlx_free(dns_hostname);
  if(!result)
    *ppeer = peer;
  else
    Curl_peer_unlink(&peer);
  return result;
}

#ifdef USE_UNIX_SOCKETS
CURLcode Curl_peer_uds_create(const struct Curl_scheme *scheme,
                              const char *path,
                              bool abstract_unix_socket,
                              struct Curl_peer **ppeer)
{
  struct Curl_peer *peer = NULL;
  size_t pathlen = path ? strlen(path) : 0;
  CURLcode result = CURLE_OK;

  if(!scheme)
    return CURLE_FAILED_INIT;
  if(!pathlen)
    return CURLE_FAILED_INIT;

  /* NUL terminator already part of struct */
  peer = curlx_calloc(1, sizeof(*peer) + pathlen);
  if(!peer) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  peer->refcount = 1;
  peer->scheme = scheme;
  peer->unix_socket = TRUE;
  peer->abstract = abstract_unix_socket;
  memcpy(peer->user_hostname, path, pathlen);
  peer->hostname = peer->user_hostname;

out:
  if(!result)
    *ppeer = peer;
  else
    Curl_peer_unlink(&peer);
  return result;
}
#endif /* USE_UNIX_SOCKETS */

void Curl_peer_link(struct Curl_peer **pdest, struct Curl_peer *src)
{
  if(*pdest != src) {
    Curl_peer_unlink(pdest);
    *pdest = src;
    if(src) {
      DEBUGASSERT(src->refcount < UINT32_MAX);
      src->refcount++;
    }
  }
}

void Curl_peer_unlink(struct Curl_peer **ppeer)
{
  if(*ppeer) {
    struct Curl_peer *peer = *ppeer;

    DEBUGASSERT(peer->refcount);
    *ppeer = NULL;
    if(peer->refcount)
      peer->refcount--;
    if(!peer->refcount) {
      if(peer->user_hostname != peer->hostname)
        curlx_free(peer->hostname);
      curlx_free(peer);
    }
  }
}

bool Curl_peer_equal(struct Curl_peer *p1, struct Curl_peer *p2)
{
  return (p1 == p2) ||
         (p1 && p2 &&
          (p1->scheme == p2->scheme) &&
          (p1->port == p2->port) &&
          (p1->ipv6scope_id == p2->ipv6scope_id) &&
          curl_strequal(p1->hostname, p2->hostname));
}

bool Curl_peer_same_destination(struct Curl_peer *p1, struct Curl_peer *p2)
{
  return (p1 == p2) ||
         (p1 && p2 &&
          (p1->ipv6 == p2->ipv6) &&
          (p1->unix_socket == p2->unix_socket) &&
          (p1->port == p2->port) &&
          (p1->ipv6scope_id == p2->ipv6scope_id) &&
          curl_strequal(p1->hostname, p2->hostname));
}

CURLcode Curl_peer_from_url(CURLU *uh, struct Curl_easy *data,
                            uint16_t port_override,
                            uint32_t ipv6scopeid_override,
                            struct urlpieces *up,
                            struct Curl_peer **ppeer)
{
  const struct Curl_scheme *scheme;
  const char *hostname = "";
  char *ipv6zoneid = NULL;
  CURLUcode uc;
  uint16_t port = 0;
  uint32_t ipv6scopeid = 0;
  CURLcode result;

  Curl_peer_unlink(ppeer);

  curlx_safefree(up->scheme);
  uc = curl_url_get(uh, CURLUPART_SCHEME, &up->scheme, 0);
  if(uc)
    return Curl_uc_to_curlcode(uc);
  scheme = Curl_get_scheme(up->scheme);
  if(!scheme) {
    failf(data, "Protocol \"%s\" not supported%s", up->scheme,
          data->state.this_is_a_follow ? " (in redirect)" : "");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  curlx_safefree(up->hostname);
  uc = curl_url_get(uh, CURLUPART_HOST, &up->hostname, 0);
  if(uc) {
    /* absent hostname only ok when protocol is NONETWORK */
    if(!(scheme->flags & PROTOPT_NONETWORK))
      return CURLE_OUT_OF_MEMORY;
  }
  else if(strlen(up->hostname) > MAX_URL_LEN) {
    failf(data, "Too long hostname (maximum is %d)", MAX_URL_LEN);
    return CURLE_URL_MALFORMAT;
  }
  else
    hostname = up->hostname;

  curlx_safefree(up->port);
  if(port_override) {
    /* if set, we use this instead of the port possibly given in the URL */
    char portbuf[16];
    curl_msnprintf(portbuf, sizeof(portbuf), "%d", port_override);
    uc = curl_url_set(uh, CURLUPART_PORT, portbuf, 0);
    if(uc) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    else
      port = port_override;
  }
  else {
    uc = curl_url_get(uh, CURLUPART_PORT, &up->port, CURLU_DEFAULT_PORT);
    if(uc) {
      if(uc == CURLUE_OUT_OF_MEMORY) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      else if(!(scheme->flags & PROTOPT_NONETWORK)) {
        result = CURLE_URL_MALFORMAT;
        goto out;
      }
      /* no port ok when not a network scheme */
    }
    else {
      const char *p = up->port;
      curl_off_t offt;
      if(curlx_str_number(&p, &offt, 0xffff))
        return CURLE_URL_MALFORMAT;
      port = (uint16_t)offt;
    }
  }

  if(ipv6scopeid_override)
    /* Override any scope id from an url zone. */
    ipv6scopeid = ipv6scopeid_override;
  else {
    if(curl_url_get(uh, CURLUPART_ZONEID, &ipv6zoneid, 0) ==
       CURLUE_OUT_OF_MEMORY) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  result = Curl_peer_create(scheme, hostname, strlen(hostname),
                            port, ipv6zoneid, ipv6scopeid,
                            ppeer);
  if(result) {
    failf(data, "Error %d creating peer for %s:%u",
          result, hostname, port);
    goto out;
  }

out:
  curlx_free(ipv6zoneid);
  return result;
}

#ifndef CURL_DISABLE_PROXY

#ifdef USE_UNIX_SOCKETS
#define UNIX_SOCKET_PREFIX "localhost"
#endif

CURLcode Curl_peer_from_proxy_url(CURLU *uh,
                                  struct Curl_easy *data,
                                  const char *url,
                                  uint8_t proxytype,
                                  struct Curl_peer **ppeer,
                                  uint8_t *pproxytype)
{
  char *scheme = NULL;
  char *portptr = NULL;
  char *host = NULL;
  char *zoneid = NULL;
  const struct Curl_scheme *curl_scheme = NULL;
  uint16_t port = CURL_DEFAULT_PROXY_PORT;
#ifdef USE_UNIX_SOCKETS
  bool is_socks = FALSE;
#endif
  CURLUcode uc;
  CURLcode result = CURLE_OK;

  uc = curl_url_get(uh, CURLUPART_SCHEME, &scheme,
                    CURLU_NON_SUPPORT_SCHEME | CURLU_NO_GUESS_SCHEME);
  if(uc) {
    if(uc == CURLUE_OUT_OF_MEMORY) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    /* url came without scheme, the passed `proxytype` determines it */
    switch(proxytype) {
    case CURLPROXY_HTTP:
    case CURLPROXY_HTTP_1_0:
      curl_scheme = &Curl_scheme_http;
      break;
    case CURLPROXY_HTTPS:
    case CURLPROXY_HTTPS2:
      curl_scheme = &Curl_scheme_https;
      break;
    case CURLPROXY_SOCKS4:
      curl_scheme = &Curl_scheme_socks4;
      break;
    case CURLPROXY_SOCKS4A:
      curl_scheme = &Curl_scheme_socks4a;
      break;
    case CURLPROXY_SOCKS5:
      curl_scheme = &Curl_scheme_socks5;
      break;
    case CURLPROXY_SOCKS5_HOSTNAME:
      curl_scheme = &Curl_scheme_socks5h;
      break;
    default:
      failf(data, "Unsupported proxy type %u for \'%s\'", proxytype, url);
      result = CURLE_COULDNT_RESOLVE_PROXY;
      goto error;
    }
  }
  else {
    curl_scheme = Curl_get_scheme(scheme);
    if(curl_scheme == &Curl_scheme_https) {
      proxytype = (proxytype != CURLPROXY_HTTPS2) ?
        CURLPROXY_HTTPS : CURLPROXY_HTTPS2;
    }
    else if(curl_scheme == &Curl_scheme_socks5h)
      proxytype = CURLPROXY_SOCKS5_HOSTNAME;
    else if(curl_scheme == &Curl_scheme_socks5)
      proxytype = CURLPROXY_SOCKS5;
    else if(curl_scheme == &Curl_scheme_socks4a)
      proxytype = CURLPROXY_SOCKS4A;
    else if((curl_scheme == &Curl_scheme_socks4) ||
            (curl_scheme == &Curl_scheme_socks))
      proxytype = CURLPROXY_SOCKS4;
    else if(curl_scheme == &Curl_scheme_http) {
      proxytype = (uint8_t)((proxytype != CURLPROXY_HTTP_1_0) ?
        CURLPROXY_HTTP : CURLPROXY_HTTP_1_0);
    }
    else {
      /* Any other xxx:// reject! */
      failf(data, "Unsupported proxy scheme for \'%s\'", url);
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }
  }
  DEBUGASSERT(curl_scheme);

  if(IS_HTTPS_PROXY(proxytype) &&
     !Curl_ssl_supports(data, SSLSUPP_HTTPS_PROXY)) {
    failf(data, "Unsupported proxy \'%s\', libcurl is built without the "
          "HTTPS-proxy support.", url);
    result = CURLE_NOT_BUILT_IN;
    goto error;
  }

  switch(curl_scheme->family) {
  case CURLPROTO_SOCKS:
#ifdef USE_UNIX_SOCKETS
    is_socks = TRUE;
#endif
    break;
  case CURLPROTO_HTTP:
    break;
  default:
    failf(data, "Unsupported proxy protocol for \'%s\'", url);
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  uc = curl_url_get(uh, CURLUPART_PORT, &portptr, CURLU_NO_DEFAULT_PORT);
  if(uc == CURLUE_OUT_OF_MEMORY) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  if(portptr) {
    curl_off_t num;
    const char *p = portptr;
    if(!curlx_str_number(&p, &num, UINT16_MAX))
      port = (uint16_t)num;
    /* Should we not error out when the port number is invalid? */
    curlx_free(portptr);
  }
  else {
    /* No port in url, take the set one or the scheme's default */
    if(data->set.proxyport)
      port = data->set.proxyport;
    else
      port = curl_scheme->defport;
  }

  /* now, clone the proxy hostname */
  uc = curl_url_get(uh, CURLUPART_HOST, &host, CURLU_URLDECODE);
  if(uc) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

#ifdef USE_UNIX_SOCKETS
  if(is_socks && curl_strequal(UNIX_SOCKET_PREFIX, host)) {
    char *path = NULL;
    uc = curl_url_get(uh, CURLUPART_PATH, &path, CURLU_URLDECODE);
    if(uc) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    /* path will be "/", if no path was found */
    if(strcmp("/", path)) {
      curlx_free(host);
      host = curl_maprintf(UNIX_SOCKET_PREFIX "%s", path);
      if(!host) {
        curlx_free(path);
        result = CURLE_OUT_OF_MEMORY;
        goto error;
      }
    }
    curlx_free(path);
  }
#endif /* USE_UNIX_SOCKETS */

  uc = curl_url_get(uh, CURLUPART_ZONEID, &zoneid, 0);
  if(uc == CURLUE_OUT_OF_MEMORY) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  *pproxytype = proxytype;
  result = Curl_peer_create(curl_scheme, host, strlen(host), port,
                            zoneid, 0, ppeer);

error:
  curlx_free(zoneid);
  curlx_free(host);
  curlx_free(scheme);
#ifdef DEBUGBUILD
  if(!result)
    DEBUGASSERT(*ppeer);
#endif
  return result;
}

#endif /* !CURL_DISABLE_PROXY */
