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

#ifndef CURL_DISABLE_PROXY

#include "urldata.h"
#include "curl_trc.h"
#include "protocol.h"
#include "proxy.h"
#include "http_proxy.h"
#include "strcase.h"
#include "url.h"
#include "vauth/vauth.h"
#include "curlx/inet_pton.h"
#include "curlx/strparse.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/*
 * cidr4_match() returns TRUE if the given IPv4 address is within the
 * specified CIDR address range.
 *
 * @unittest 1614
 */
UNITTEST bool cidr4_match(const char *ipv4,    /* 1.2.3.4 address */
                          const char *network, /* 1.2.3.4 address */
                          unsigned int bits);
UNITTEST bool cidr4_match(const char *ipv4,    /* 1.2.3.4 address */
                          const char *network, /* 1.2.3.4 address */
                          unsigned int bits)
{
  unsigned int address = 0;
  unsigned int check = 0;

  if(bits > 32)
    /* strange input */
    return FALSE;

  if(curlx_inet_pton(AF_INET, ipv4, &address) != 1)
    return FALSE;
  if(curlx_inet_pton(AF_INET, network, &check) != 1)
    return FALSE;

  if(bits && (bits != 32)) {
    unsigned int mask = 0xffffffff << (32 - bits);
    unsigned int haddr = htonl(address);
    unsigned int hcheck = htonl(check);
#if 0
    curl_mfprintf(stderr, "Host %s (%x) network %s (%x) "
                  "bits %u mask %x => %x\n",
                  ipv4, haddr, network, hcheck, bits, mask,
                  (haddr ^ hcheck) & mask);
#endif
    if((haddr ^ hcheck) & mask)
      return FALSE;
    return TRUE;
  }
  return address == check;
}

/* @unittest 1614 */
UNITTEST bool cidr6_match(const char *ipv6, const char *network,
                          unsigned int bits);
UNITTEST bool cidr6_match(const char *ipv6, const char *network,
                          unsigned int bits)
{
#ifdef USE_IPV6
  unsigned int bytes;
  unsigned int rest;
  unsigned char address[16];
  unsigned char check[16];

  if(!bits)
    bits = 128;

  bytes = bits / 8;
  rest = bits & 0x07;
  if((bytes > 16) || ((bytes == 16) && rest))
    return FALSE;
  if(curlx_inet_pton(AF_INET6, ipv6, address) != 1)
    return FALSE;
  if(curlx_inet_pton(AF_INET6, network, check) != 1)
    return FALSE;
  if(bytes && memcmp(address, check, bytes))
    return FALSE;
  if(rest && ((address[bytes] ^ check[bytes]) & (0xff << (8 - rest))))
    return FALSE;

  return TRUE;
#else
  (void)ipv6;
  (void)network;
  (void)bits;
  return FALSE;
#endif
}

enum nametype {
  TYPE_HOST,
  TYPE_IPV4,
  TYPE_IPV6
};

static bool match_host(const char *token, size_t tokenlen,
                       const char *name, size_t namelen)
{
  bool match = FALSE;

  /* ignore trailing dots in the token to check */
  if(token[tokenlen - 1] == '.')
    tokenlen--;

  if(tokenlen && (*token == '.')) {
    /* ignore leading token dot as well */
    token++;
    tokenlen--;
  }
  /* A: example.com matches 'example.com'
     B: www.example.com matches 'example.com'
     C: nonexample.com DOES NOT match 'example.com'
  */
  if(tokenlen == namelen)
    /* case A, exact match */
    match = curl_strnequal(token, name, namelen);
  else if(tokenlen < namelen) {
    /* case B, tailmatch domain */
    match = (name[namelen - tokenlen - 1] == '.') &&
            curl_strnequal(token, name + (namelen - tokenlen), tokenlen);
  }
  /* case C passes through, not a match */
  return match;
}

static bool match_ip(int type, const char *token, size_t tokenlen,
                     const char *name)
{
  char *slash;
  unsigned int bits = 0;
  char checkip[128];
  if(tokenlen >= sizeof(checkip))
    /* this cannot match */
    return FALSE;
  /* copy the check name to a temp buffer */
  memcpy(checkip, token, tokenlen);
  checkip[tokenlen] = 0;

  slash = strchr(checkip, '/');
  /* if the slash is part of this token, use it */
  if(slash) {
    curl_off_t value;
    const char *p = &slash[1];
    if(curlx_str_number(&p, &value, 128) || *p)
      return FALSE;
    /* a too large value is rejected in the cidr function below */
    bits = (unsigned int)value;
    *slash = 0; /* null-terminate there */
  }
  if(type == TYPE_IPV6)
    return cidr6_match(name, checkip, bits);
  else
    return cidr4_match(name, checkip, bits);
}

/****************************************************************
 * Checks if the host is in the noproxy list. returns TRUE if it matches and
 * therefore the proxy should NOT be used.
 ****************************************************************/
/* @unittest 1614 */
UNITTEST bool proxy_check_noproxy(const char *name, const char *no_proxy);
UNITTEST bool proxy_check_noproxy(const char *name, const char *no_proxy)
{
  /*
   * If we do not have a hostname at all, like for example with a FILE
   * transfer, we have nothing to interrogate the noproxy list with.
   */
  if(!name || name[0] == '\0')
    return FALSE;

  /* no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   */
  if(no_proxy && no_proxy[0]) {
    const char *p = no_proxy;
    size_t namelen;
    char address[16];
    enum nametype type = TYPE_HOST;
    if(!strcmp("*", no_proxy))
      return TRUE;

    /* NO_PROXY was specified and it was not only an asterisk */

    /* Check if name is an IP address; if not, assume it being a hostname. */
    namelen = strlen(name);
    if(curlx_inet_pton(AF_INET, name, &address) == 1)
      type = TYPE_IPV4;
#ifdef USE_IPV6
    else if(curlx_inet_pton(AF_INET6, name, &address) == 1)
      type = TYPE_IPV6;
#endif
    else {
      /* ignore trailing dots in the hostname */
      if(name[namelen - 1] == '.')
        namelen--;
    }

    while(*p) {
      const char *token;
      size_t tokenlen = 0;

      /* pass blanks */
      curlx_str_passblanks(&p);

      token = p;
      /* pass over the pattern */
      while(*p && !ISBLANK(*p) && (*p != ',')) {
        p++;
        tokenlen++;
      }

      if(tokenlen) {
        bool match = FALSE;
        if(type == TYPE_HOST)
          match = match_host(token, tokenlen, name, namelen);
        else
          match = match_ip(type, token, tokenlen, name);

        if(match)
          return TRUE;
      }

      /* pass blanks after pattern */
      curlx_str_passblanks(&p);
      /* if not a comma, this ends the loop */
      if(*p != ',')
        break;
      /* pass any number of commas */
      while(*p == ',')
        p++;
    } /* while(*p) */
  } /* NO_PROXY was specified and it was not only an asterisk */

  return FALSE;
}

#ifndef CURL_DISABLE_HTTP

/****************************************************************
 * Detect what (if any) proxy to use. Remember that this selects a host
 * name and is not limited to HTTP proxies only.
 * The returned pointer must be freed by the caller.
 ****************************************************************/
static char *proxy_detect_proxy(struct Curl_easy *data,
                                const struct Curl_scheme *scheme)
{
  /* If proxy was not specified, we check for default proxy environment
   * variables, to enable i.e Lynx compliance:
   *
   * http_proxy=http://some.server.dom:port/
   * https_proxy=http://some.server.dom:port/
   * ftp_proxy=http://some.server.dom:port/
   * no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   * all_proxy=http://some.server.dom:port/
   *   (seems to exist for the CERN www lib. Probably
   *   the first to check for.)
   *
   * For compatibility, the all-uppercase versions of these variables are
   * checked if the lowercase versions do not exist.
   */
  const char *env_name = NULL;
  char *proxy = NULL;
  char name_buf[20];

  /* Try scheme specific env var first, unless http(s).
   * lowercase first, then uppercase. */
  if((scheme != &Curl_scheme_https) && (scheme != &Curl_scheme_http)) {
    curl_msnprintf(name_buf, sizeof(name_buf), "%s_proxy", scheme->name);
    env_name = name_buf;
    proxy = curl_getenv(env_name);
    if(!proxy) {
      Curl_strntoupper(name_buf, name_buf, sizeof(name_buf));
      proxy = curl_getenv(env_name);
    }
  }

  if(!proxy &&
     ((scheme == &Curl_scheme_https) || (scheme == &Curl_scheme_wss))) {
    /* Not found, check 'https' env vars, also for 'wss'.
     * Again, first lowercase then uppercase. */
    env_name = "https_proxy";
    proxy = curl_getenv(env_name);
    if(!proxy) {
      env_name = "HTTPS_PROXY";
      proxy = curl_getenv(env_name);
    }
  }
  else if(!proxy &&
          ((scheme == &Curl_scheme_http) || (scheme == &Curl_scheme_ws))) {
    /* Not found, check 'http' env vars, also for 'ws'.
     * We do NOT try the uppercase version 'HTTP_PROXY' because of
     * security reasons:
     *
     * When curl is used in a webserver application
     * environment (cgi or php), this environment variable can
     * be controlled by the web server user by setting the
     * http header 'Proxy:' to some value.
     *
     * This can cause 'internal' http/ftp requests to be
     * arbitrarily redirected by any external attacker.
     */
    env_name = "http_proxy";
    proxy = curl_getenv(env_name);
  }

  if(!proxy) {
    /* still not found, last resort checks. */
    env_name = "all_proxy";
    proxy = curl_getenv(env_name);
    if(!proxy) {
      env_name = "ALL_PROXY";
      proxy = curl_getenv(env_name);
    }
  }

  if(proxy)
    infof(data, "Uses proxy env variable %s == '%s'", env_name, proxy);

  return proxy;
}
#endif /* CURL_DISABLE_HTTP */

/*
 * If this is supposed to use a proxy, we need to figure out the proxy
 * hostname, so that we can reuse an existing connection
 * that may exist registered to the same proxy host.
 */
static CURLcode parse_proxy(struct Curl_easy *data,
                            const char *proxy,
                            bool for_pre_proxy,
                            struct proxy_info *proxyinfo)
{
  char *proxyuser = NULL;
  char *proxypasswd = NULL;
  char *scheme = NULL;
  CURLcode result = CURLE_OK;
  /* Set the start proxy type for URL scheme guessing */
  uint8_t proxytype = for_pre_proxy ? CURLPROXY_SOCKS4 : data->set.proxytype;
  CURLU *uhp = curl_url();
  CURLUcode uc;

  if(!uhp) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  /* When parsing the proxy, allowing non-supported schemes since we have
     these made up ones for proxies. Guess scheme for URLs without it. */
  uc = curl_url_set(uhp, CURLUPART_URL, proxy,
                    CURLU_NON_SUPPORT_SCHEME | CURLU_GUESS_SCHEME);
  if(!uc) {
    /* parsed okay as a URL - only update proxytype when scheme was explicit */
    uc = curl_url_get(uhp, CURLUPART_SCHEME, &scheme, CURLU_NO_GUESS_SCHEME);
    if(!uc) {
      result = Curl_scheme_to_proxytype(data, scheme, &proxytype, proxy);
      if(result)
        goto error;
    }
    else if(uc != CURLUE_NO_SCHEME) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    /* else: no explicit scheme, keep the configured proxytype */
  }
  else {
    failf(data, "Unsupported proxy syntax in \'%s\': %s", proxy,
          curl_url_strerror(uc));
    result = CURLE_COULDNT_RESOLVE_PROXY;
    goto error;
  }

  result = Curl_peer_from_proxy_url(uhp, data, proxy, proxytype,
                                    &proxyinfo->peer, &proxytype);
  if(result)
    goto error;

  switch(proxytype) {
    case CURLPROXY_HTTP:
    case CURLPROXY_HTTP_1_0:
    case CURLPROXY_HTTPS:
    case CURLPROXY_HTTPS2:
    case CURLPROXY_HTTPS3:
      if(for_pre_proxy) {
        failf(data, "Unsupported pre-proxy type for \'%s\'", proxy);
        result = CURLE_COULDNT_RESOLVE_PROXY;
        goto error;
      }
      break;
    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      break;
    default:
      failf(data, "Unsupported proxy type %u for \'%s\'", proxytype, proxy);
      result = CURLE_COULDNT_RESOLVE_PROXY;
      goto error;
  }

  /* Is there a username and password given in this proxy URL? */
  uc = curl_url_get(uhp, CURLUPART_USER, &proxyuser, CURLU_URLDECODE);
  if(uc && (uc != CURLUE_NO_USER)) {
    result = Curl_uc_to_curlcode(uc);
    goto error;
  }
  uc = curl_url_get(uhp, CURLUPART_PASSWORD, &proxypasswd, CURLU_URLDECODE);
  if(uc && (uc != CURLUE_NO_PASSWORD)) {
    result = Curl_uc_to_curlcode(uc);
    goto error;
  }

  if(proxyuser || proxypasswd) {
    result = Curl_creds_create(proxyuser, proxypasswd, NULL, NULL,
                               data->set.str[STRING_PROXY_SERVICE_NAME],
                               CREDS_URL, &proxyinfo->creds);
    if(result)
      goto error;
  }
  else if(!for_pre_proxy &&
          (data->set.str[STRING_PROXYUSERNAME] ||
           data->set.str[STRING_PROXYPASSWORD] ||
           data->set.str[STRING_PROXY_SERVICE_NAME])) {
    /* No user/passwd in URL, if this is not a pre-proxy, the
     * CURLOPT_PROXY* settings apply. */
    result = Curl_creds_create(data->set.str[STRING_PROXYUSERNAME],
                               data->set.str[STRING_PROXYPASSWORD],
                               NULL, NULL,
                               data->set.str[STRING_PROXY_SERVICE_NAME],
                               CREDS_OPTION, &proxyinfo->creds);
  }
  else
    Curl_creds_unlink(&proxyinfo->creds);

  proxyinfo->proxytype = proxytype;

error:
  curlx_free(scheme);
  curlx_free(proxyuser);
  curlx_free(proxypasswd);
  curl_url_cleanup(uhp);
#ifdef DEBUGBUILD
  if(!result) {
    DEBUGASSERT(proxyinfo);
    DEBUGASSERT(proxyinfo->peer);
  }
#endif
  return result;
}

/* Is transfer's origin exempted from proxy use? */
static bool proxy_do_not_proxy(struct Curl_easy *data)
{
  const char *no_proxy;
  char *env_no_proxy = NULL;
  bool do_not_proxy;

  /* no proxying if the transfer does not use the network */
  if(data->state.origin->scheme->flags & PROTOPT_NONETWORK)
    return TRUE;

  no_proxy = data->set.str[STRING_NOPROXY];
  if(!no_proxy) {
    const char *p = "no_proxy";
    env_no_proxy = curl_getenv(p);
    if(!env_no_proxy) {
      p = "NO_PROXY";
      env_no_proxy = curl_getenv(p);
    }
    if(env_no_proxy)
      infof(data, "Uses proxy env variable %s == '%s'", p, env_no_proxy);
    no_proxy = env_no_proxy;
  }

  do_not_proxy = proxy_check_noproxy(data->state.origin->hostname, no_proxy);
  curlx_safefree(env_no_proxy);
  return do_not_proxy;
}

CURLcode Curl_proxy_init_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  char *proxy = NULL;
  char *pre_proxy = NULL;
  bool do_env_detect = TRUE;
  CURLcode result = CURLE_OK;

  /* Enforce no proxy use unless we decide to use one */
  conn->bits.origin_is_proxy = FALSE;
  DEBUGASSERT(!conn->socks_proxy.peer);
  DEBUGASSERT(!conn->http_proxy.peer);

  if(proxy_do_not_proxy(data))
    goto out;

  /*************************************************************
   * Detect what (if any) proxy to use
   *************************************************************/
  /* the empty config strings disable proxy use and env detects */
  if(data->set.str[STRING_PROXY]) {
    if(*data->set.str[STRING_PROXY]) {
      proxy = curlx_strdup(data->set.str[STRING_PROXY]);
      /* if global proxy is set, this is it */
      if(!proxy) {
        failf(data, "memory shortage");
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
    }
    else
      do_env_detect = FALSE;
  }

  if(data->set.str[STRING_PRE_PROXY]) {
    if(*data->set.str[STRING_PRE_PROXY]) {
      pre_proxy = curlx_strdup(data->set.str[STRING_PRE_PROXY]);
      /* if global socks proxy is set, this is it */
      if(!pre_proxy) {
        failf(data, "memory shortage");
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
    }
    else
      do_env_detect = FALSE;
  }

#ifndef CURL_DISABLE_HTTP
  /* None configured, detect possible proxy from environment. */
  if(!proxy && !pre_proxy && do_env_detect)
    proxy = proxy_detect_proxy(data, conn->scheme);
#else
  (void)do_env_detect;
#endif /* CURL_DISABLE_HTTP */

  if(!proxy && !pre_proxy)
    goto out;

  if(pre_proxy) {
    result = parse_proxy(data, pre_proxy, TRUE, &conn->socks_proxy);
    if(result)
      goto out;
  }

  if(proxy) {
    result = parse_proxy(data, proxy, FALSE, &conn->http_proxy);
    if(result)
      goto out;

    switch(conn->http_proxy.proxytype) {
    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      /* Whoops, it is not an HTTP proxy */
      if(pre_proxy) {
        /* and we already have a SOCKS pre-proxy. Cannot have both */
        failf(data, "Having a SOCKS pre-proxy and proxy is not "
              "supported with \'%s\'", proxy);
        result = CURLE_COULDNT_RESOLVE_PROXY;
        goto out;
      }
      /* switch */
      conn->socks_proxy = conn->http_proxy;
      memset(&conn->http_proxy, 0, sizeof(conn->http_proxy));
      break;
    default:
      /* all other types are HTTP */
      break;
    }
  }

  if(conn->socks_proxy.peer) {
    DEBUGASSERT(!CURL_PROXY_IS_ANY_HTTP(conn->socks_proxy.proxytype));
  }

#ifdef CURL_DISABLE_HTTP
  if(conn->http_proxy.peer) {
    /* asking for an HTTP proxy is a bit funny when HTTP is disabled... */
    result = CURLE_UNSUPPORTED_PROTOCOL;
    goto out;
  }

#else /* CURL_DISABLE_HTTP */
  if(conn->http_proxy.peer) {
    const struct Curl_scheme *scheme = data->state.origin->scheme;
    bool tunnel_proxy = (bool)data->set.tunnel_thru_httpproxy;
    DEBUGASSERT(CURL_PROXY_IS_ANY_HTTP(conn->http_proxy.proxytype));

    if(!tunnel_proxy) {
      /* Decide if we tunnel through proxy automatically */
      if(conn->via_peer) {
        /* With connect-to, we always tunnel */
        tunnel_proxy = TRUE;
      }
      else if(scheme->flags & PROTOPT_SSL) {
        /* If the transfer is supposed to be secure, we tunnel */
        tunnel_proxy = TRUE;
      }
      else if(scheme->flags & PROTOPT_HTTP_PROXY_TUNNEL) {
        /* transfer scheme required tunneling */
        tunnel_proxy = TRUE;
      }
      else if(!(scheme->protocol & PROTO_FAMILY_HTTP) &&
              !(scheme->flags & PROTOPT_PROXY_AS_HTTP)) {
        /* Cannot delegate transfer URL to HTTP proxy */
        tunnel_proxy = TRUE;
      }
    }

    if(!tunnel_proxy) {
      /* HTTP proxy used in forwarding mode. This means the connection
       * is really to the proxy and NOT the origin of the transfer. */
      DEBUGASSERT(!conn->via_peer);
      Curl_peer_link(&conn->origin, conn->http_proxy.peer);
      conn->scheme = conn->http_proxy.peer->scheme;
      conn->bits.origin_is_proxy = TRUE;
    }

#ifndef CURL_DISABLE_DIGEST_AUTH
    if(!Curl_safecmp(data->state.envproxy, proxy)) {
      /* proxy changed */
      Curl_auth_digest_cleanup(&data->state.proxydigest);
      curlx_free(data->state.envproxy);
      data->state.envproxy = curlx_strdup(proxy);
    }
#endif
  }
#endif /* !CURL_DISABLE_HTTP */

out:
  curlx_free(pre_proxy);
  curlx_free(proxy);
  return result;
}

#endif /* CURL_DISABLE_PROXY */
