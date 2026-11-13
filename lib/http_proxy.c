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

#include "http_proxy.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_PROXY)

#include "curl_trc.h"
#include "http.h"
#include "url.h"
#include "cfilters.h"
#include "cf-h1-proxy.h"
#include "cf-h2-proxy.h"
#include "connect.h"
#include "vauth/vauth.h"
#include "vquic/vquic.h"
#include "curlx/strparse.h"

struct proxy_custom_ctx {
  struct Curl_easy *data;
  int httpversion;
};

static CURLcode prox_custom_ignore(void *user_data,
                                   struct Curl_str *name,
                                   struct Curl_str *value,
                                   const char *orig_data)
{
  struct proxy_custom_ctx *x = user_data;

  (void)value;
  (void)orig_data;
  if(x->data->state.http_host &&
     /* a Host: header was sent already, do not pass on any custom Host:
        header as that will produce *two* in the same request! */
     curlx_str_casecompare2(name, STRCONST("Host")))
    return CURLE_AGAIN;
  else if(x->data->state.httpreq == HTTPREQ_POST_FORM &&
          /* this header (extended by formdata.c) is sent later */
          curlx_str_casecompare2(name, STRCONST("Content-Type")))
    return CURLE_AGAIN;
  else if(x->data->state.httpreq == HTTPREQ_POST_MIME &&
          /* this header is sent later */
          curlx_str_casecompare2(name, STRCONST("Content-Type")))
    return CURLE_AGAIN;
  else if(x->data->req.authneg &&
          /* while doing auth neg, do not allow the custom length since
             we will force length zero then */
          curlx_str_casecompare2(name, STRCONST("Content-Length")))
    return CURLE_AGAIN;
  else if((x->httpversion >= 20) &&
          curlx_str_casecompare2(name, STRCONST("Transfer-Encoding")))
    return CURLE_AGAIN;
  /* HTTP/2 and HTTP/3 do not support chunked requests */
  else if((curlx_str_casecompare2(name, STRCONST("Authorization")) ||
           curlx_str_casecompare2(name, STRCONST("Cookie"))) &&
          /* be careful of sending this potentially sensitive header to
             other hosts */
          !Curl_auth_allowed_to_host(x->data))
    return CURLE_AGAIN;
  return CURLE_OK;
}

static CURLcode dynhds_add_custom(struct Curl_easy *data,
                                  bool is_connect, int httpversion,
                                  struct dynhds *hds)
{
  struct connectdata *conn = data->conn;
  struct curl_slist *h[2];
  int numlists = 0; /* by default */
  struct proxy_custom_ctx ign_ctx;
  int i;

  if(is_connect) {
    h[numlists++] = data->set.sep_headers ?
                    data->set.proxyheaders : data->set.headers;
  }
  else if(conn->bits.origin_is_proxy) {
    h[numlists++] = data->set.headers;
    if(data->set.sep_headers)
      h[numlists++] = data->set.proxyheaders;
  }
  else {
    h[numlists++] = data->set.headers;
  }

  /* loop through one or two lists, adding custom headers */
  ign_ctx.data = data;
  ign_ctx.httpversion = httpversion;
  for(i = 0; i < numlists; i++) {
    CURLcode result =
      Curl_dynhds_add_slist(hds, h[i], prox_custom_ignore, &ign_ctx);
      if(result)
        return result;
  }

  return CURLE_OK;
}

struct cf_proxy_ctx {
  struct Curl_peer *peer; /* proxy */
  struct Curl_peer *tunnel_peer; /* tunnel destination */
  uint8_t proxytype;
  uint8_t tunnel_transport;
  BIT(sub_filter_installed);
};

static int proxy_http_ver_major(proxy_http_ver ver)
{
  switch(ver) {
  case PROXY_HTTP_V1:
    return 11;
  case PROXY_HTTP_V2:
    return 20;
  case PROXY_HTTP_V3:
    return 30;
  }
  return 0;
}

static CURLcode http_proxy_create_CONNECT(struct httpreq **preq,
                                          struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          struct Curl_peer *peer,
                                          struct Curl_peer *dest,
                                          proxy_http_ver ver)
{
  struct connectdata *conn = CF_CONN(cf);
  char *authority = NULL;
  const char *ua;
  int httpversion = proxy_http_ver_major(ver);
  CURLcode result;
  struct httpreq *req = NULL;

  (void)peer;
  authority = curl_maprintf("%s%s%s:%u",
                            dest->ipv6 ? "[" : "",
                            dest->hostname,
                            dest->ipv6 ? "]" : "",
                            dest->port);
  if(!authority) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_http_req_make(&req, STRCONST("CONNECT"),
                              NULL, 0, authority, strlen(authority),
                              NULL, 0);
  if(result)
    goto out;

  /* Setup the proxy-authorization header, if any */
  result = Curl_http_output_auth(data, conn, req->method, HTTPREQ_GET,
                                 req->authority, NULL, TRUE);
  if(result)
    goto out;

  /* If user is not overriding Host: header, we add for HTTP/1.x */
  if(ver == PROXY_HTTP_V1 &&
     !Curl_checkProxyheaders(data, conn, STRCONST("Host"))) {
    result = Curl_dynhds_cadd(&req->headers, "Host", authority);
    if(result)
      goto out;
  }

  if(data->req.hd_proxy_auth) {
    result = Curl_dynhds_h1_cadd_line(&req->headers,
                                      data->req.hd_proxy_auth);
    if(result)
      goto out;
  }

  ua = CURL_EASY_STR(data, STRING_USERAGENT);
  if(!Curl_checkProxyheaders(data, conn, STRCONST("User-Agent")) &&
     ua && *ua) {
    result = Curl_dynhds_cadd(&req->headers, "User-Agent", ua);
    if(result)
      goto out;
  }

  if(ver == PROXY_HTTP_V1 &&
     !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection"))) {
    result = Curl_dynhds_cadd(&req->headers, "Proxy-Connection", "Keep-Alive");
    if(result)
      goto out;
  }

  result = dynhds_add_custom(data, TRUE, httpversion, &req->headers);

out:
  if(result && req) {
    Curl_http_req_free(req);
    req = NULL;
  }
  curlx_safefree(data->req.hd_proxy_auth); /* not needed anymore */
  curlx_free(authority);
  *preq = req;
  return result;
}

static CURLcode http_proxy_create_CONNECTUDP(struct httpreq **preq,
                                             struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             struct Curl_peer *peer,
                                             struct Curl_peer *dest,
                                             proxy_http_ver ver)
{
  struct connectdata *conn = CF_CONN(cf);
  const char *proxy_scheme = "http", *ua;
  int httpversion = proxy_http_ver_major(ver);
  char *authority = NULL;
  char *path = NULL;
  char *encoded_host = NULL;
  struct httpreq *req = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  if(conn->http_proxy.proxytype == CURLPROXY_HTTPS ||
     conn->http_proxy.proxytype == CURLPROXY_HTTPS2 ||
     conn->http_proxy.proxytype == CURLPROXY_HTTPS3)
    proxy_scheme = "https";

  authority = curl_maprintf("%s%s%s:%d",
                            peer->ipv6 ? "[" : "",
                            peer->hostname,
                            peer->ipv6 ? "]" : "",
                            peer->port);
  if(!authority)
    goto out;

  if(dest->ipv6) {
    /* RFC 9298: colons in IPv6 addresses MUST be percent-encoded
     * in the URI template (e.g. "2001:db8::1" -> "2001%3Adb8%3A%3A1") */
    const char *s = dest->hostname;
    char *d;
    size_t hlen = strlen(s);
    encoded_host = curlx_malloc(hlen * 3 + 1);
    if(!encoded_host) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    d = encoded_host;
    while(*s) {
      if(*s == ':') {
        *d++ = '%';
        *d++ = '3';
        *d++ = 'A';
      }
      else
        *d++ = *s;
      s++;
    }
    *d = '\0';
    path = curl_maprintf("/.well-known/masque/udp/%s/%u/",
                         encoded_host, (unsigned int)dest->port);
  }
  else {
    path = curl_maprintf("/.well-known/masque/udp/%s/%u/",
                         dest->hostname, (unsigned int)dest->port);
  }
  if(!path)
    goto out;

  if(ver == PROXY_HTTP_V1) {
    result = Curl_http_req_make(&req, "GET", CURL_CSTRLEN("GET"),
                                proxy_scheme, strlen(proxy_scheme),
                                authority, strlen(authority),
                                path, strlen(path));
  }
  else if(ver == PROXY_HTTP_V2 || ver == PROXY_HTTP_V3) {
    result = Curl_http_req_make(&req, STRCONST("CONNECT"),
                                proxy_scheme, strlen(proxy_scheme),
                                authority, strlen(authority),
                                path, strlen(path));
  }
  else
    result = CURLE_FAILED_INIT;
  if(result)
    goto out;

  if(ver > PROXY_HTTP_V1) {
    /* Pseudo header must go first */
    result = Curl_dynhds_cadd(&req->headers, ":Protocol", "connect-udp");
  }
  else {
    /* If user is not overriding Host: header, we add for HTTP/1.x */
    if(!Curl_checkProxyheaders(data, conn, STRCONST("Host"))) {
      result = Curl_dynhds_cadd(&req->headers, "Host", authority);
    }
    if(!result &&
       !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection"))) {
      result = Curl_dynhds_cadd(&req->headers, "Proxy-Connection",
                                "Keep-Alive");
    }
    if(!result)
      result = Curl_dynhds_cadd(&req->headers, "Connection", "Upgrade");
    if(!result)
      result = Curl_dynhds_cadd(&req->headers, "Upgrade", "connect-udp");
  }

  if(!result)
    /* Setup the proxy-authorization header, if any */
    result = Curl_http_output_auth(data, conn, req->method, HTTPREQ_GET,
                                   req->authority, NULL, TRUE);
  if(!result && data->req.hd_proxy_auth)
    result = Curl_dynhds_h1_cadd_line(&req->headers,
                                      data->req.hd_proxy_auth);
  if(!result)
    result = Curl_dynhds_cadd(&req->headers, "Capsule-Protocol", "?1");
  if(!result) {
    ua = CURL_EASY_STR(data, STRING_USERAGENT);
    if(ver == PROXY_HTTP_V1 &&
       !Curl_checkProxyheaders(data, conn, STRCONST("User-Agent")) &&
       ua && *ua) {
      result = Curl_dynhds_cadd(&req->headers, "User-Agent", ua);
      if(result)
        goto out;
    }
  }
  if(!result)
    result = dynhds_add_custom(data, TRUE, httpversion, &req->headers);

out:
  if(result && req) {
    Curl_http_req_free(req);
    req = NULL;
  }
  curlx_safefree(data->req.hd_proxy_auth); /* not needed any more */
  curlx_free(authority);
  curlx_free(path);
  curlx_free(encoded_host);
  *preq = req;
  return result;
}

CURLcode Curl_http_proxy_create_tunnel_request(
    struct httpreq **preq, struct Curl_cfilter *cf,
    struct Curl_easy *data, struct Curl_peer *peer, struct Curl_peer *dest,
    proxy_http_ver ver, bool udp_tunnel)
{
  CURLcode result = udp_tunnel ?
    http_proxy_create_CONNECTUDP(preq, cf, data, peer, dest, ver) :
    http_proxy_create_CONNECT(preq, cf, data, peer, dest, ver);
  if(result)
    return result;

  infof(data, "Establishing %s proxy %stunnel to %s:%u",
        (ver == PROXY_HTTP_V2) ? "HTTP/2" :
        (ver == PROXY_HTTP_V3) ? "HTTP/3" : "HTTP",
        udp_tunnel ? "UDP " : "",
        dest->user_hostname, dest->port);
  return CURLE_OK;
}

CURLcode Curl_http_proxy_inspect_tunnel_response(
    struct Curl_cfilter *cf, struct Curl_easy *data,
    struct http_resp *resp, bool udp_tunnel,
    proxy_inspect_result *presult)
{
  struct dynhds_entry *capsule_protocol = NULL;
  struct dynhds_entry *auth_reply = NULL;
  uint32_t i, header_count;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(resp);

  header_count = Curl_dynhds_count(&resp->headers);
  infof(data, "CONNECT%s Response Status %d",
        udp_tunnel ? "-UDP" : "", resp->status);
  infof(data, "Response Headers (%u total):", header_count);
  for(i = 0; i < header_count; i++) {
    struct dynhds_entry *entry = Curl_dynhds_getn(&resp->headers, i);
    if(entry)
      infof(data, "  %s: %s", entry->name, entry->value);
  }

  if(resp->status == 407) {
    auth_reply = Curl_dynhds_cget(&resp->headers, "Proxy-Authenticate");
  }

  if(auth_reply) {
    CURL_TRC_CF(data, cf, "[0] CONNECT%s: fwd auth header '%s'",
                udp_tunnel ? "-UDP" : "", auth_reply->value);
    result = Curl_http_input_auth(data, resp->status == 407,
                                  auth_reply->value);
    if(result)
      return result;
    if(data->req.newurl) {
      curlx_safefree(data->req.newurl);
      *presult = PROXY_INSPECT_AUTH_RETRY;
      return CURLE_OK;
    }
  }

  if(udp_tunnel) {
    if(resp->status / 100 == 2) {
      capsule_protocol = Curl_dynhds_cget(&resp->headers,
                                           "capsule-protocol");
      if(capsule_protocol) {
        if(!strncmp(capsule_protocol->value, "?1", 2) &&
           !capsule_protocol->value[2]) {
          infof(data, "CONNECT-UDP tunnel established, response %d",
                resp->status);
          *presult = PROXY_INSPECT_OK;
          return CURLE_OK;
        }
        failf(data, "Failed to establish CONNECT-UDP tunnel, response %d, "
              "unsupported capsule-protocol value '%s'",
              resp->status, capsule_protocol->value);
        *presult = PROXY_INSPECT_FAILED;
        return CURLE_COULDNT_CONNECT;
      }
      else {
        /* NOTE proxies may not set capsule protocol in the headers */
        infof(data, "CONNECT-UDP tunnel established, response %d "
                    "but no capsule-protocol header found", resp->status);
        *presult = PROXY_INSPECT_OK;
        return CURLE_OK;
      }
    }
    else {
      failf(data, "Failed to establish CONNECT-UDP tunnel, "
                  "response %d", resp->status);
      *presult = PROXY_INSPECT_FAILED;
      return CURLE_COULDNT_CONNECT;
    }
  }

  if(resp->status / 100 == 2) {
    infof(data, "CONNECT tunnel established, response %d", resp->status);
    *presult = PROXY_INSPECT_OK;
    return CURLE_OK;
  }

  *presult = PROXY_INSPECT_FAILED;
  return CURLE_COULDNT_CONNECT;
}

static CURLcode http_proxy_cf_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  CURLcode result;
  bool udp_tunnel = TRNSPRT_IS_DGRAM(ctx->tunnel_transport);

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  CURL_TRC_CF(data, cf, "CONNECT%s", udp_tunnel ? "-UDP" : "");
connect_sub:
  /* in case of h3_proxy, cf->next will be NULL initially */
  if(cf->next) {
    result = cf->next->cft->do_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  if(!ctx->sub_filter_installed) {
    const char *alpn = NULL;

    /* in case of h3_proxy, cf->next will be NULL initially */
    if(cf->next) {
      alpn = Curl_conn_cf_get_alpn_negotiated(cf->next, data);
    }

    if(alpn)
      infof(data, "CONNECT%s: '%s' negotiated",
            udp_tunnel ? "-UDP" : "", alpn);
    else if(!alpn) {
      /* No ALPN, proxytype rules. Fake ALPN */
      infof(data, "CONNECT%s: no ALPN negotiated", udp_tunnel ? "-UDP" : "");
      switch(ctx->proxytype) {
      case CURLPROXY_HTTP_1_0:
        alpn = "http/1.0";
        break;
      case CURLPROXY_HTTPS2:
        alpn = "h2";
        break;
      case CURLPROXY_HTTPS3:
        alpn = "h3";
        break;
      default:
        alpn = "http/1.1";
        break;
      }
    }

    if(!strcmp(alpn, "http/1.0")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/1.0");
      result = Curl_cf_h1_proxy_insert_after(cf, data, ctx->peer,
                                             ctx->tunnel_peer, 10, udp_tunnel);
      if(result)
        goto out;
    }
    else if(!strcmp(alpn, "http/1.1")) {
      int httpversion = (ctx->proxytype == CURLPROXY_HTTP_1_0) ? 10 : 11;
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/1.%d",
                  httpversion % 10);
      result = Curl_cf_h1_proxy_insert_after(cf, data, ctx->peer,
                                             ctx->tunnel_peer,
                                             httpversion, udp_tunnel);
      if(result)
        goto out;
    }
#ifdef USE_NGHTTP2
    else if(!strcmp(alpn, "h2")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/2");
      result = Curl_cf_h2_proxy_insert_after(cf, data, ctx->peer,
                                             ctx->tunnel_peer, udp_tunnel);
      if(result)
        goto out;
    }
#endif /* USE_NGHTTP2 */
#if defined(USE_PROXY_HTTP3) && defined(USE_NGHTTP3) && \
  defined(USE_NGTCP2) && defined(USE_OPENSSL)
    else if(!strcmp(alpn, "h3")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/3");
      result = Curl_cf_h3_proxy_insert_after(cf, data, ctx->peer, ctx->peer,
                                             ctx->tunnel_peer,
                                             ctx->tunnel_transport);
      if(result)
        goto out;
    }
#endif /* USE_PROXY_HTTP3 && USE_NGHTTP3 && USE_NGTCP2 && USE_OPENSSL */
    else {
      failf(data, "CONNECT%s: negotiated ALPN '%s' not supported",
            udp_tunnel ? "-UDP" : "", alpn);
      result = CURLE_COULDNT_CONNECT;
      goto out;
    }

    ctx->sub_filter_installed = TRUE;
    /* after we installed the filter "below" us, we call connect
     * on out sub-chain again.
     */
    goto connect_sub;
  }
  else {
    /* subchain connected and we had already installed the protocol filter.
     * This means the protocol tunnel is established, we are done. */
    DEBUGASSERT(ctx->sub_filter_installed);
    result = CURLE_OK;
  }

out:
  if(!result) {
    cf->connected = TRUE;
    *done = TRUE;
  }
  return result;
}

static CURLcode cf_http_proxy_query(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    int query, int *pres1, void *pres2)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  switch(query) {
  case CF_QUERY_HOST_PORT:
    *pres1 = (int)ctx->tunnel_peer->port;
    *((const char **)pres2) = ctx->tunnel_peer->hostname;
    return CURLE_OK;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static void cf_https_proxy_ctx_free(struct cf_proxy_ctx *ctx)
{
  if(ctx) {
    Curl_peer_unlink(&ctx->peer);
    Curl_peer_unlink(&ctx->tunnel_peer);
    curlx_free(ctx);
  }
}

static void http_proxy_cf_destroy(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  if(ctx) {
    CURL_TRC_CF(data, cf, "destroy");
    cf_https_proxy_ctx_free(ctx);
  }
}

struct Curl_cftype Curl_cft_http_proxy = {
  "HTTP-PROXY",
  CF_TYPE_IP_CONNECT | CF_TYPE_PROXY | CF_TYPE_SETUP,
  0,
  http_proxy_cf_destroy,
  http_proxy_cf_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_http_proxy_query,
};

CURLcode Curl_cf_http_proxy_insert_after(struct Curl_cfilter *cf_at,
                                         struct Curl_easy *data,
                                         struct Curl_peer *peer,
                                         struct Curl_peer *tunnel_peer,
                                         uint8_t tunnel_transport,
                                         uint8_t proxytype)
{
  struct Curl_cfilter *cf;
  struct cf_proxy_ctx *ctx = NULL;
  CURLcode result;

  (void)data;
  if(!peer || !tunnel_peer)
    return CURLE_FAILED_INIT;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  Curl_peer_link(&ctx->peer, peer);
  Curl_peer_link(&ctx->tunnel_peer, tunnel_peer);
  ctx->proxytype = proxytype;
  ctx->tunnel_transport = tunnel_transport;

  result = Curl_cf_create(&cf, &Curl_cft_http_proxy, ctx);
  if(result)
    goto out;
  ctx = NULL;
  Curl_conn_cf_insert_after(cf_at, cf);

out:
  cf_https_proxy_ctx_free(ctx);
  return result;
}

uint8_t Curl_http_proxy_transport(uint8_t proxytype)
{
  switch(proxytype) {
  case CURLPROXY_HTTPS3:
    return TRNSPRT_QUIC;
  default:
    return TRNSPRT_TCP;
  }
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY */
