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

struct peer_parse {
  const struct Curl_scheme *scheme;
  struct Curl_str host_user;
  struct Curl_str host;
  struct Curl_str zoneid;
  char *tmp_host_user;
  char *tmp_host;
  char *tmp_zoneid;
  uint32_t scopeid;
  uint16_t port;
  bool ipv6;
  bool unix_socket;
  bool abstract_uds;
};

static void peer_parse_clear(struct peer_parse *pp)
{
  curlx_free(pp->tmp_host_user);
  curlx_free(pp->tmp_host);
  curlx_free(pp->tmp_zoneid);
  memset(pp, 0, sizeof(*pp));
}

static CURLcode peer_create(struct peer_parse *pp,
                            struct Curl_peer **ppeer)
{
  struct Curl_peer *peer = NULL;
  CURLcode result = CURLE_OK;
  size_t zone_alen = 0, host_alen = 0;

  if(!pp || !pp->scheme)
    return CURLE_FAILED_INIT;
  if(!pp->host.len && !(pp->scheme->flags & PROTOPT_NONETWORK))
    return CURLE_FAILED_INIT;

  if((pp->host.str != pp->host_user.str) ||
     (pp->host.len != pp->host_user.len)) {
    host_alen = pp->host.len + 1;
  }
  zone_alen = pp->zoneid.len ? (pp->zoneid.len + 1) : 0;

  /* null-terminator already part of struct */
  peer = curlx_calloc(1, sizeof(*peer) +
                         pp->host_user.len + host_alen + zone_alen);
  if(!peer) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  peer->refcount = 1;
  peer->scheme = pp->scheme;
  peer->hostname = peer->user_hostname;
  peer->port = pp->port;
  peer->scopeid = pp->scopeid;
  peer->ipv6 = pp->ipv6;
  peer->unix_socket = pp->unix_socket;
  peer->abstract_uds = pp->abstract_uds;

  if(pp->host_user.len)
    memcpy(peer->user_hostname, pp->host_user.str, pp->host_user.len);

  if(host_alen) {
    peer->hostname = peer->user_hostname + pp->host_user.len + 1;
    memcpy(peer->hostname, pp->host.str, pp->host.len);
  }

  if(zone_alen) {
    peer->zoneid = peer->user_hostname + pp->host_user.len + 1 + host_alen;
    memcpy(peer->zoneid, pp->zoneid.str, pp->zoneid.len);
#ifdef USE_IPV6
    /* Determine scope_id if not already provided */
    if(!peer->scopeid) {
      const char *p = peer->zoneid;
      curl_off_t scope;
      if(!curlx_str_number(&p, &scope, UINT_MAX)) {
        /* A plain number, use it directly as a scope id. */
        peer->scopeid = (uint32_t)scope;
      }
#ifdef HAVE_IF_NAMETOINDEX
      else {
        /* Zone identifier is not numeric */
        unsigned int idx = 0;
        idx = if_nametoindex(peer->zoneid);
        if(idx) {
          peer->scopeid = (uint32_t)idx;
        }
        else {
          /* Do we want to return an error here? */
        }
      }
#endif /* HAVE_IF_NAMETOINDEX */
    }
#endif /* USE_IPV6 */
  }

out:
  if(!result)
    *ppeer = peer;
  else
    Curl_peer_unlink(&peer);
  return result;
}

static CURLcode peer_parse_host(struct Curl_easy *data,
                                struct peer_parse *pp,
                                bool scan_for_ipv6)
{
  if(!pp || !pp->host_user.str || !pp->host_user.len)
    return CURLE_FAILED_INIT;

  if(pp->host_user.str[0] == '[') {
    const char *s = pp->host_user.str + 1;
    struct Curl_str tmp;
    if(curlx_str_until(&s, &tmp, pp->host_user.len - 1, ']'))
      return CURLE_URL_MALFORMAT;

    if(!Curl_looks_like_ipv6(tmp.str, tmp.len, TRUE,
                             &pp->host, &pp->zoneid)) {
      failf(data, "Invalid IPv6 address format in '%.*s'",
            (int)pp->host_user.len, pp->host_user.str);
      return CURLE_URL_MALFORMAT;
    }
    pp->ipv6 = TRUE;
  }
  else {
#ifdef USE_IDN
    if(!Curl_is_ASCII_str(&pp->host_user)) {
      CURLcode result;
      if(!pp->tmp_host_user) {
        /* need a null-terminated string for IDN */
        pp->tmp_host_user = curlx_memdup0(pp->host_user.str,
                                          pp->host_user.len);
        if(!pp->tmp_host_user)
          return CURLE_OUT_OF_MEMORY;
      }
      result = Curl_idn_decode(pp->tmp_host_user, &pp->tmp_host);
      if(result)
        return result;
      pp->host.str = pp->tmp_host;
      pp->host.len = strlen(pp->host.str);
    }
    else
#endif
    if(scan_for_ipv6 &&
       Curl_looks_like_ipv6(pp->host_user.str, pp->host_user.len, TRUE,
                            &pp->host, &pp->zoneid)) {
      pp->ipv6 = TRUE;
    }
    else
      pp->host = pp->host_user;
  }
  return CURLE_OK;
}

CURLcode Curl_peer_create(struct Curl_easy *data,
                          const struct Curl_scheme *scheme,
                          const char *hostname,
                          uint16_t port,
                          struct Curl_peer **ppeer)
{
  struct peer_parse pp;
  CURLcode result;

  Curl_peer_unlink(ppeer);
  memset(&pp, 0, sizeof(pp));
  pp.scheme = scheme;
  pp.host_user.str = hostname;
  pp.host_user.len = strlen(hostname);
  pp.port = port;

  result = peer_parse_host(data, &pp, TRUE);
  if(!result)
    result = peer_create(&pp, ppeer);

  peer_parse_clear(&pp);
  return result;
}

#ifdef USE_UNIX_SOCKETS
CURLcode Curl_peer_uds_create(const struct Curl_scheme *scheme,
                              const char *path,
                              bool abstract_unix_socket,
                              struct Curl_peer **ppeer)
{
  struct peer_parse pp;
  size_t pathlen = path ? strlen(path) : 0;
  CURLcode result = CURLE_OK;

  Curl_peer_unlink(ppeer);
  memset(&pp, 0, sizeof(pp));
  if(!scheme)
    return CURLE_FAILED_INIT;
  if(!pathlen)
    return CURLE_FAILED_INIT;

  pp.scheme = scheme;
  pp.host_user.str = pp.host.str = path;
  pp.host_user.len = pp.host.len = pathlen;
  pp.unix_socket = TRUE;
  pp.abstract_uds = abstract_unix_socket;

  result = peer_create(&pp, ppeer);
  peer_parse_clear(&pp);
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
      curlx_free(peer);
    }
  }
}

bool Curl_peer_equal(struct Curl_peer *p1, struct Curl_peer *p2)
{
  return (p1 == p2) ||
         (p1 && p2 &&
          (p1->scheme == p2->scheme) &&
          Curl_peer_same_destination(p1, p2));
}

static bool peer_same_hostname(struct Curl_peer *p1, struct Curl_peer *p2)
{
  /* UNIX domain socket paths must be compared case-sensitive,
   * as many filesystem are like that. */
  return (p1->unix_socket == p2->unix_socket) &&
         (p1->abstract_uds == p2->abstract_uds) &&
         (p1->ipv6 == p2->ipv6) &&
         (p1->unix_socket ?
          !strcmp(p1->hostname, p2->hostname) :
          curl_strequal(p1->hostname, p2->hostname));
}

bool Curl_peer_same_destination(struct Curl_peer *p1, struct Curl_peer *p2)
{
  return (p1 == p2) ||
         (p1 && p2 &&
          (p1->port == p2->port) &&
          peer_same_hostname(p1, p2) &&
          (p1->scopeid == p2->scopeid) &&
          (p1->scopeid || curl_strequal(p1->zoneid, p2->zoneid)));
}

CURLcode Curl_peer_from_url(CURLU *uh, struct Curl_easy *data,
                            uint16_t port_override,
                            uint32_t scopeid_override,
                            struct urlpieces *up,
                            struct Curl_peer **ppeer)
{
  struct peer_parse pp;
  char *zoneid = NULL;
  CURLUcode uc;
  CURLcode result;

  Curl_peer_unlink(ppeer);
  memset(&pp, 0, sizeof(pp));

  curlx_safefree(up->scheme);
  uc = curl_url_get(uh, CURLUPART_SCHEME, &up->scheme, 0);
  if(uc)
    return Curl_uc_to_curlcode(uc);
  pp.scheme = Curl_get_scheme(up->scheme);
  if(!pp.scheme) {
    failf(data, "Protocol \"%s\" not supported%s", up->scheme,
          data->state.this_is_a_follow ? " (in redirect)" : "");
    result = CURLE_UNSUPPORTED_PROTOCOL;
    goto out;
  }

  curlx_safefree(up->hostname);
  uc = curl_url_get(uh, CURLUPART_HOST, &up->hostname, 0);
  if(uc) {
    if((uc == CURLUE_NO_HOST) && (pp.scheme->flags & PROTOPT_NONETWORK))
      ; /* acceptable */
    else {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }
  else if(strlen(up->hostname) > MAX_URL_LEN) {
    failf(data, "Too long hostname (maximum is %d)", MAX_URL_LEN);
    result = CURLE_URL_MALFORMAT;
    goto out;
  }

  pp.host_user.str = up->hostname ? up->hostname : "";
  pp.host_user.len = strlen(pp.host_user.str);
  if(pp.host_user.len) {
    result = peer_parse_host(data, &pp, FALSE);
    if(result)
      goto out;
  }
  else
    pp.host = pp.host_user;

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
      pp.port = port_override;
  }
  else {
    uc = curl_url_get(uh, CURLUPART_PORT, &up->port, CURLU_DEFAULT_PORT);
    if(uc) {
      if(uc == CURLUE_OUT_OF_MEMORY) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      else if(!(pp.scheme->flags & PROTOPT_NONETWORK)) {
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
      pp.port = (uint16_t)offt;
    }
  }

  if(scopeid_override)
    /* Override any scope id from an url zone. */
    pp.scopeid = scopeid_override;
  else {
    if(curl_url_get(uh, CURLUPART_ZONEID, &zoneid, 0) ==
       CURLUE_OUT_OF_MEMORY) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    if(zoneid) {
      pp.zoneid.str = zoneid;
      pp.zoneid.len = strlen(zoneid);
    }
  }

  result = peer_create(&pp, ppeer);
  if(result)
    failf(data, "Error %d creating peer for %s:%u",
          result, pp.host_user.str, pp.port);

out:
  peer_parse_clear(&pp);
  curlx_free(zoneid);
  return result;
}

/* Parse a "host:port" string to connect to into a peer.
 * IPv6 addresses might appear in brackets or without them. */
CURLcode Curl_peer_from_connect_to(struct Curl_easy *data,
                                   const struct Curl_peer *dest,
                                   const char *connect_to,
                                   struct Curl_peer **ppeer)
{
  struct peer_parse pp;
  const char *portstr = NULL;
  CURLcode result;

  Curl_peer_unlink(ppeer);
  memset(&pp, 0, sizeof(pp));
  if(!connect_to || !*connect_to)
    return CURLE_FAILED_INIT;

  pp.scheme = dest->scheme;

  /* detect and extract RFC6874-style IPv6-addresses */
  if(connect_to[0] == '[') {
    const char *s = strchr(connect_to + 1, ']');
    if(!s) {
      failf(data, "Invalid IPv6 address format in '%s'", connect_to);
      result = CURLE_SETOPT_OPTION_SYNTAX;
      goto out;
    }
    portstr = strchr(s, ':');
    pp.host_user.str = connect_to;
    pp.host_user.len = s - pp.host_user.str + 1;
    pp.ipv6 = TRUE;
  }
  else {
    portstr = strchr(connect_to, ':');
    pp.host_user.str = connect_to;
    pp.host_user.len = portstr ?
      (size_t)(portstr - connect_to) : strlen(connect_to);
  }

  if(!pp.host_user.len) { /* no hostname found, only port switch */
    pp.host_user.str = dest->user_hostname;
    pp.host_user.len = strlen(dest->user_hostname);
  }

  result = peer_parse_host(data, &pp, FALSE);
  if(result)
    goto out;

  if(portstr && portstr[1]) {
    const char *p = portstr + 1;
    curl_off_t portparse;
    if(curlx_str_number(&p, &portparse, 0xffff)) {
      failf(data, "No valid port number in '%s'", connect_to);
      result = CURLE_SETOPT_OPTION_SYNTAX;
      goto out;
    }
    pp.port = (uint16_t)portparse; /* we know it will fit */
  }
  else
    pp.port = dest->port;

#ifndef USE_IPV6
  if(pp.ipv6) {
    failf(data, "Use of IPv6 in *_CONNECT_TO without IPv6 support built-in");
    result = CURLE_NOT_BUILT_IN;
    goto out;
  }
#endif

  result = peer_create(&pp, ppeer);
  CURL_TRC_M(data, "connect-to peer_create2 -> %d", result);

out:
  CURL_TRC_M(data, "parse connect_to peer: %s -> %d", connect_to, result);
  peer_parse_clear(&pp);
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
  struct peer_parse pp;
  char *scheme = NULL;
  char *portptr = NULL;
#ifdef USE_UNIX_SOCKETS
  bool is_socks = FALSE;
#endif
  CURLUcode uc;
  CURLcode result = CURLE_OK;

  Curl_peer_unlink(ppeer);
  memset(&pp, 0, sizeof(pp));
  pp.port = CURL_DEFAULT_PROXY_PORT;
  uc = curl_url_get(uh, CURLUPART_SCHEME, &scheme,
                    CURLU_NON_SUPPORT_SCHEME | CURLU_NO_GUESS_SCHEME);
  if(uc) {
    if(uc == CURLUE_OUT_OF_MEMORY) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    /* url came without scheme, the passed `proxytype` determines it */
    switch(proxytype) {
    case CURLPROXY_HTTP:
    case CURLPROXY_HTTP_1_0:
      pp.scheme = &Curl_scheme_http;
      break;
    case CURLPROXY_HTTPS:
    case CURLPROXY_HTTPS2:
      pp.scheme = &Curl_scheme_https;
      break;
    case CURLPROXY_SOCKS4:
      pp.scheme = &Curl_scheme_socks4;
      break;
    case CURLPROXY_SOCKS4A:
      pp.scheme = &Curl_scheme_socks4a;
      break;
    case CURLPROXY_SOCKS5:
      pp.scheme = &Curl_scheme_socks5;
      break;
    case CURLPROXY_SOCKS5_HOSTNAME:
      pp.scheme = &Curl_scheme_socks5h;
      break;
    default:
      failf(data, "Unsupported proxy type %u for \'%s\'", proxytype, url);
      result = CURLE_COULDNT_RESOLVE_PROXY;
      goto out;
    }
  }
  else {
    pp.scheme = Curl_get_scheme(scheme);
    if(pp.scheme == &Curl_scheme_https) {
      proxytype = (proxytype != CURLPROXY_HTTPS2) ?
        CURLPROXY_HTTPS : CURLPROXY_HTTPS2;
    }
    else if(pp.scheme == &Curl_scheme_socks5h)
      proxytype = CURLPROXY_SOCKS5_HOSTNAME;
    else if(pp.scheme == &Curl_scheme_socks5)
      proxytype = CURLPROXY_SOCKS5;
    else if(pp.scheme == &Curl_scheme_socks4a)
      proxytype = CURLPROXY_SOCKS4A;
    else if((pp.scheme == &Curl_scheme_socks4) ||
            (pp.scheme == &Curl_scheme_socks))
      proxytype = CURLPROXY_SOCKS4;
    else if(pp.scheme == &Curl_scheme_http) {
      proxytype = (uint8_t)((proxytype != CURLPROXY_HTTP_1_0) ?
        CURLPROXY_HTTP : CURLPROXY_HTTP_1_0);
    }
    else {
      /* Any other xxx:// reject! */
      failf(data, "Unsupported proxy scheme for \'%s\'", url);
      result = CURLE_COULDNT_CONNECT;
      goto out;
    }
  }
  DEBUGASSERT(pp.scheme);

  if(IS_HTTPS_PROXY(proxytype) &&
     !Curl_ssl_supports(data, SSLSUPP_HTTPS_PROXY)) {
    failf(data, "Unsupported proxy \'%s\', libcurl is built without the "
          "HTTPS-proxy support.", url);
    result = CURLE_NOT_BUILT_IN;
    goto out;
  }

  switch(pp.scheme->family) {
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
    goto out;
  }

  uc = curl_url_get(uh, CURLUPART_PORT, &portptr, CURLU_NO_DEFAULT_PORT);
  if(uc == CURLUE_OUT_OF_MEMORY) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  if(portptr) {
    curl_off_t num;
    const char *p = portptr;
    if(!curlx_str_number(&p, &num, UINT16_MAX))
      pp.port = (uint16_t)num;
    /* Should we not error out when the port number is invalid? */
    curlx_free(portptr);
  }
  else {
    /* No port in url, take the set one or the scheme's default */
    if(data->set.proxyport)
      pp.port = data->set.proxyport;
    else
      pp.port = pp.scheme->defport;
  }

  /* now, clone the proxy hostname */
  uc = curl_url_get(uh, CURLUPART_HOST, &pp.tmp_host_user, CURLU_URLDECODE);
  if(uc) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  pp.host_user.str = pp.tmp_host_user;
  pp.host_user.len = strlen(pp.tmp_host_user);

#ifdef USE_UNIX_SOCKETS
  if(is_socks && curl_strequal(UNIX_SOCKET_PREFIX, pp.tmp_host_user)) {
    uc = curl_url_get(uh, CURLUPART_PATH, &pp.tmp_host, CURLU_URLDECODE);
    if(uc) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    /* path will be "/", if no path was found */
    if(strcmp("/", pp.tmp_host)) {
      pp.host.str = pp.tmp_host;
      pp.host.len = strlen(pp.tmp_host);
      pp.unix_socket = TRUE;
    }
    else {
      pp.host = pp.host_user;
    }
  }
#endif /* USE_UNIX_SOCKETS */

  if(!pp.host.len) {
    result = peer_parse_host(data, &pp, FALSE);
    if(result)
      goto out;
  }

  uc = curl_url_get(uh, CURLUPART_ZONEID, &pp.tmp_zoneid, 0);
  if(uc == CURLUE_OUT_OF_MEMORY) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  if(pp.tmp_zoneid) {
    pp.zoneid.str = pp.tmp_zoneid;
    pp.zoneid.len = strlen(pp.tmp_zoneid);
  }

  *pproxytype = proxytype;
  result = peer_create(&pp, ppeer);

out:
  peer_parse_clear(&pp);
  curlx_free(scheme);
#ifdef DEBUGBUILD
  if(!result)
    DEBUGASSERT(*ppeer);
#endif
  return result;
}

#endif /* !CURL_DISABLE_PROXY */
