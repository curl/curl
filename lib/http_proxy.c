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

#include <curl/curl.h>
#include "sendf.h"
#include "http.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "cfilters.h"
#include "cf-h1-proxy.h"
#include "cf-h2-proxy.h"
#include "cf-h3-proxy.h"
#include "connect.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"
#include "vauth/vauth.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static bool hd_name_eq(const char *n1, size_t n1len,
                       const char *n2, size_t n2len)
{
  return (n1len == n2len) ? curl_strnequal(n1, n2, n1len) : FALSE;
}

static CURLcode dynhds_add_custom(struct Curl_easy *data,
                                  bool is_connect, int httpversion,
                                  bool is_udp, struct dynhds *hds)
{
  struct connectdata *conn = data->conn;
  const char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; /* by default */
  int i;

  enum Curl_proxy_use proxy;

  if(is_connect && !is_udp)
    proxy = HEADER_CONNECT;
  else if(is_connect && is_udp)
    proxy = HEADER_CONNECT_UDP;
  else
    proxy = (conn->bits.httpproxy && (!conn->bits.tunnel_proxy
            || !conn->bits.udp_tunnel_proxy)) ? HEADER_PROXY : HEADER_SERVER;

  switch(proxy) {
  case HEADER_SERVER:
    h[0] = data->set.headers;
    break;
  case HEADER_PROXY:
    h[0] = data->set.headers;
    if(data->set.sep_headers) {
      h[1] = data->set.proxyheaders;
      numlists++;
    }
    break;
  case HEADER_CONNECT:
    if(data->set.sep_headers)
      h[0] = data->set.proxyheaders;
    else
      h[0] = data->set.headers;
    break;
  case HEADER_CONNECT_UDP:
    if(data->set.sep_headers)
      h[0] = data->set.proxyheaders;
    else
      h[0] = data->set.headers;
    break;
  }

  /* loop through one or two lists */
  for(i = 0; i < numlists; i++) {
    for(headers = h[i]; headers; headers = headers->next) {
      const char *name, *value;
      size_t namelen, valuelen;

      /* There are 2 quirks in place for custom headers:
       * 1. setting only 'name:' to suppress a header from being sent
       * 2. setting only 'name;' to send an empty (illegal) header
       */
      ptr = strchr(headers->data, ':');
      if(ptr) {
        name = headers->data;
        namelen = ptr - headers->data;
        ptr++; /* pass the colon */
        curlx_str_passblanks(&ptr);
        if(*ptr) {
          value = ptr;
          valuelen = strlen(value);
        }
        else {
          /* quirk #1, suppress this header */
          continue;
        }
      }
      else {
        ptr = strchr(headers->data, ';');

        if(!ptr) {
          /* neither : nor ; in provided header value. We seem
           * to ignore this silently */
          continue;
        }

        name = headers->data;
        namelen = ptr - headers->data;
        ptr++; /* pass the semicolon */
        curlx_str_passblanks(&ptr);
        if(!*ptr) {
          /* quirk #2, send an empty header */
          value = "";
          valuelen = 0;
        }
        else {
          /* this may be used for something else in the future,
           * ignore this for now */
          continue;
        }
      }

      DEBUGASSERT(name && value);
      if(data->state.aptr.host &&
         /* a Host: header was sent already, do not pass on any custom Host:
            header as that will produce *two* in the same request! */
         hd_name_eq(name, namelen, STRCONST("Host:")))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_FORM &&
              /* this header (extended by formdata.c) is sent later */
              hd_name_eq(name, namelen, STRCONST("Content-Type:")))
        ;
      else if(data->state.httpreq == HTTPREQ_POST_MIME &&
              /* this header is sent later */
              hd_name_eq(name, namelen, STRCONST("Content-Type:")))
        ;
      else if(data->req.authneg &&
              /* while doing auth neg, do not allow the custom length since
                 we will force length zero then */
              hd_name_eq(name, namelen, STRCONST("Content-Length:")))
        ;
      else if((httpversion >= 20) &&
              hd_name_eq(name, namelen, STRCONST("Transfer-Encoding:")))
        /* HTTP/2 and HTTP/3 do not support chunked requests */
        ;
      else if((hd_name_eq(name, namelen, STRCONST("Authorization:")) ||
               hd_name_eq(name, namelen, STRCONST("Cookie:"))) &&
              /* be careful of sending this potentially sensitive header to
                 other hosts */
              !Curl_auth_allowed_to_host(data))
        ;
      else {
        CURLcode result;

        result = Curl_dynhds_add(hds, name, namelen, value, valuelen);
        if(result)
          return result;
      }
    }
  }

  return CURLE_OK;
}

CURLcode Curl_http_proxy_get_destination(struct Curl_cfilter *cf,
                                         const char **phostname,
                                         int *pport, bool *pipv6_ip)
{
  DEBUGASSERT(cf);
  DEBUGASSERT(cf->conn);

  if(cf->conn->bits.conn_to_host)
    *phostname = cf->conn->conn_to_host.name;
  else if(cf->sockindex == SECONDARYSOCKET)
    *phostname = cf->conn->secondaryhostname;
  else
    *phostname = cf->conn->host.name;

  if(cf->sockindex == SECONDARYSOCKET)
    *pport = cf->conn->secondary_port;
  else if(cf->conn->bits.conn_to_port)
    *pport = cf->conn->conn_to_port;
  else
    *pport = cf->conn->remote_port;

  if(*phostname != cf->conn->host.name)
    *pipv6_ip = (strchr(*phostname, ':') != NULL);
  else
    *pipv6_ip = cf->conn->bits.ipv6_ip;

  return CURLE_OK;
}

struct cf_proxy_ctx {
  /* the protocol specific sub-filter we install during connect */
  struct Curl_cfilter *cf_protocol;
  int httpversion; /* HTTP version used to CONNECT */
};

CURLcode Curl_http_proxy_create_CONNECT(struct httpreq **preq,
                                        struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        int http_version_major)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  const char *hostname = NULL;
  char *authority = NULL;
  int port;
  bool ipv6_ip;
  CURLcode result;
  struct httpreq *req = NULL;

  result = Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);
  if(result)
    goto out;

  authority = aprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
                      ipv6_ip ?"]" : "", port);
  if(!authority) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_http_req_make(&req, "CONNECT", sizeof("CONNECT")-1,
                              NULL, 0, authority, strlen(authority),
                              NULL, 0);
  if(result)
    goto out;

  /* Setup the proxy-authorization header, if any */
  result = Curl_http_output_auth(data, cf->conn, req->method, HTTPREQ_GET,
                                 req->authority, TRUE);
  if(result)
    goto out;

  /* If user is not overriding Host: header, we add for HTTP/1.x */
  if(http_version_major == 1 &&
     !Curl_checkProxyheaders(data, cf->conn, STRCONST("Host"))) {
    result = Curl_dynhds_cadd(&req->headers, "Host", authority);
    if(result)
      goto out;
  }

  if(data->state.aptr.proxyuserpwd) {
    result = Curl_dynhds_h1_cadd_line(&req->headers,
                                      data->state.aptr.proxyuserpwd);
    if(result)
      goto out;
  }

  if(!Curl_checkProxyheaders(data, cf->conn, STRCONST("User-Agent")) &&
     data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT]) {
    result = Curl_dynhds_cadd(&req->headers, "User-Agent",
                              data->set.str[STRING_USERAGENT]);
    if(result)
      goto out;
  }

  if(http_version_major == 1 &&
    !Curl_checkProxyheaders(data, cf->conn, STRCONST("Proxy-Connection"))) {
    result = Curl_dynhds_cadd(&req->headers, "Proxy-Connection", "Keep-Alive");
    if(result)
      goto out;
  }

  result = dynhds_add_custom(data, TRUE, ctx->httpversion,
    FALSE, &req->headers);

out:
  if(result && req) {
    Curl_http_req_free(req);
    req = NULL;
  }
  free(authority);
  *preq = req;
  return result;
}

CURLcode Curl_http_proxy_create_CONNECTUDP(struct httpreq **preq,
                                           struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           int http_version_major)
{
  const char *hostname = NULL;
  char *authority = NULL;
  char *path = NULL;
  int port;
  bool ipv6_ip;
  struct cf_proxy_ctx *ctx = cf->ctx;
  CURLcode result;
  struct httpreq *req = NULL;
  char *proxy = NULL;
  char *proxy_scheme = NULL;
  char *proxy_host = NULL;
  char *proxy_port = NULL;

  proxy = data->set.str[STRING_PROXY];
  proxy_scheme = strndup(proxy, strstr(proxy, "://") - proxy);
  proxy_host = strndup(proxy + strlen(proxy_scheme) + 3,
        strchr(proxy + strlen(proxy_scheme) + 3, ':') -
                        (proxy + strlen(proxy_scheme) + 3));
  proxy_port = strdup(strchr(proxy + strlen(proxy_scheme) + 3, ':') + 1);

  result = Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);
  if(result)
    goto out;

  authority = aprintf("%s%s%s:%d", ipv6_ip ? "[" : "", proxy_host,
                      ipv6_ip ?"]" : "", atoi(proxy_port));
  if(!authority) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* MASQUE FIX: envoy and h2o has different behaviour */
  /* envoy expects path --> "/.well-known/masque/udp/<host>/<port/" */
  /* path = aprintf("/.well-known/masque/udp/%s/%d/", hostname, port); */
  /* h2o expects path --> "/<host>/<port/" */
  path = aprintf("/%s/%d/", hostname, port);

  if(!path) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(http_version_major == 1) {
    result = Curl_http_req_make(&req, "GET", sizeof("GET")-1,
                                NULL, 0, proxy, strlen(proxy),
                                path, strlen(path));
    if(result)
      goto out;
  }
  else if(http_version_major == 2 || http_version_major == 3) {
    result = Curl_http_req_make(&req, "CONNECT", sizeof("CONNECT") - 1,
                                proxy_scheme, strlen(proxy_scheme),
                                authority, strlen(authority),
                                path, strlen(path));
    if(result)
      goto out;
  }

  /* If user is not overriding Host: header, we add for HTTP/1.x */
  if(http_version_major == 1 &&
      !Curl_checkProxyheaders(data, cf->conn, STRCONST("Host"))) {
    result = Curl_dynhds_cadd(&req->headers, "Host", authority);
    if(result)
      goto out;
  }

  if(data->state.aptr.proxyuserpwd) {
    result = Curl_dynhds_h1_cadd_line(&req->headers,
                                      data->state.aptr.proxyuserpwd);
    if(result)
      goto out;
  }

  if(http_version_major == 1 &&
    !Curl_checkProxyheaders(data, cf->conn, STRCONST("User-Agent")) &&
      data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT]) {
    result = Curl_dynhds_cadd(&req->headers, "User-Agent",
                              data->set.str[STRING_USERAGENT]);
    if(result)
      goto out;
  }

  if(http_version_major == 1 &&
      !Curl_checkProxyheaders(data, cf->conn, STRCONST("Proxy-Connection"))) {
    result = Curl_dynhds_cadd(&req->headers, "Proxy-Connection", "Keep-Alive");
    if(result)
      goto out;
  }

  if(http_version_major == 1) {
    result = Curl_dynhds_cadd(&req->headers, "Connection", "Upgrade");
    if(result)
      goto out;

    result = Curl_dynhds_cadd(&req->headers, "Upgrade", "connect-udp");
    if(result)
      goto out;

    result = Curl_dynhds_cadd(&req->headers, "Capsule-Protocol", "?1");
    if(result)
      goto out;
  }
  else {
    result = Curl_dynhds_cadd(&req->headers, ":Protocol", "connect-udp");
    if(result)
      goto out;

    if(http_version_major >= 2) {
      result = Curl_dynhds_cadd(&req->headers, "Capsule-Protocol", "?1");
      if(result)
        goto out;
    }
  }

  result = dynhds_add_custom(data, TRUE, ctx->httpversion,
    TRUE, &req->headers);

out:
  if(result && req) {
    Curl_http_req_free(req);
    req = NULL;
  }
  free(authority);
  free(path);
  *preq = req;
  return result;
}

static CURLcode http_proxy_cf_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  CURLcode result;
  const char *tunnel_type;  /* Determine tunnel type once and reuse */

  tunnel_type = cf->conn->bits.udp_tunnel_proxy ?
                "CONNECT-UDP" : "CONNECT";

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  CURL_TRC_CF(data, cf, "connect");
connect_sub:
  /* in case of h3_proxy, cf->next will be NULL initially */
  if(cf->next) {
    result = cf->next->cft->do_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  if(!ctx->cf_protocol) {
    struct Curl_cfilter *cf_protocol = NULL;
    int httpversion = 0;
    const char *alpn = NULL;

    /* in case of h3_proxy, cf->next will be NULL initially */
    if(cf->next) {
      alpn = Curl_conn_cf_get_alpn_negotiated(cf->next, data);
    }
    else {
        alpn = "h3";
    }

    if(alpn)
      infof(data, "%s: '%s' negotiated", tunnel_type, alpn);
    else
      infof(data, "%s: no ALPN negotiated", tunnel_type);

    if(alpn && !strcmp(alpn, "http/1.0")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/1.0");
      infof(data, "installing subfilter for HTTP/1.0");
      result = Curl_cf_h1_proxy_insert_after(cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      httpversion = 10;
    }
    else if(!alpn || !strcmp(alpn, "http/1.1")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/1.1");
      infof(data, "installing subfilter for HTTP/1.1");
      result = Curl_cf_h1_proxy_insert_after(cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      /* Assume that without an ALPN, we are talking to an ancient one */
      httpversion = 11;
    }
#ifdef USE_NGHTTP2
    else if(!strcmp(alpn, "h2")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/2");
      infof(data, "installing subfilter for HTTP/2");
      result = Curl_cf_h2_proxy_insert_after(cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      httpversion = 20;
    }
#endif
#ifdef USE_NGHTTP3
    else if(!strcmp(alpn, "h3")) {
      CURL_TRC_CF(data, cf, "installing subfilter for HTTP/3");
      infof(data, "installing subfilter for HTTP/3");
      result = Curl_cf_h3_proxy_insert_after(&cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      httpversion = 31;
    }
#endif
    else {
      failf(data, "%s: negotiated ALPN '%s' not supported", tunnel_type, alpn);
      result = CURLE_COULDNT_CONNECT;
      goto out;
    }

    ctx->cf_protocol = cf_protocol;
    ctx->httpversion = httpversion;
    /* after we installed the filter "below" us, we call connect
     * on out sub-chain again.
     */
    goto connect_sub;
  }
  else {
    /* subchain connected and we had already installed the protocol filter.
     * This means the protocol tunnel is established, we are done.
     */
    DEBUGASSERT(ctx->cf_protocol);
    result = CURLE_OK;
  }

out:
  if(!result) {
    cf->connected = TRUE;
    *done = TRUE;
  }
  return result;
}

CURLcode Curl_cf_http_proxy_query(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int query, int *pres1, void *pres2)
{
  switch(query) {
  case CF_QUERY_HOST_PORT:
    *pres1 = (int)cf->conn->http_proxy.port;
    *((const char **)pres2) = cf->conn->http_proxy.host.name;
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

static void http_proxy_cf_destroy(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_proxy_ctx *ctx = cf->ctx;

  (void)data;
  CURL_TRC_CF(data, cf, "destroy");
  free(ctx);
}

static void http_proxy_cf_close(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_proxy_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf->connected = FALSE;
  if(ctx->cf_protocol) {
    struct Curl_cfilter *f;
    /* if someone already removed it, we assume he also
     * took care of destroying it. */
    for(f = cf->next; f; f = f->next) {
      if(f == ctx->cf_protocol) {
        /* still in our sub-chain */
        Curl_conn_cf_discard_sub(cf, ctx->cf_protocol, data, FALSE);
        break;
      }
    }
    ctx->cf_protocol = NULL;
  }
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

struct Curl_cftype Curl_cft_http_proxy = {
  "HTTP-PROXY",
  CF_TYPE_IP_CONNECT|CF_TYPE_PROXY,
  0,
  http_proxy_cf_destroy,
  http_proxy_cf_connect,
  http_proxy_cf_close,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_http_proxy_query,
};

CURLcode Curl_cf_http_proxy_insert_after(struct Curl_cfilter *cf_at,
                                         struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  struct cf_proxy_ctx *ctx = NULL;
  CURLcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = Curl_cf_create(&cf, &Curl_cft_http_proxy, ctx);
  if(result)
    goto out;
  ctx = NULL;
  Curl_conn_cf_insert_after(cf_at, cf);

out:
  free(ctx);
  return result;
}

#endif /* ! CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY */
