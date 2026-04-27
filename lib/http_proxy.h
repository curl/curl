#ifndef HEADER_CURL_HTTP_PROXY_H
#define HEADER_CURL_HTTP_PROXY_H
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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include "urldata.h"

enum Curl_proxy_use {
  HEADER_SERVER,  /* direct to server */
  HEADER_PROXY,   /* regular request to proxy */
  HEADER_CONNECT, /* sending CONNECT to a proxy */
  HEADER_CONNECT_UDP /* sending CONNECT-UDP to a proxy */
};

/* HTTP version for proxy tunnel request creation */
typedef enum {
  PROXY_HTTP_V1 = 1,
  PROXY_HTTP_V2 = 2,
  PROXY_HTTP_V3 = 3
} proxy_http_ver;

/* Result from inspecting a proxy tunnel response */
typedef enum {
  PROXY_INSPECT_OK,         /* Tunnel established */
  PROXY_INSPECT_FAILED,     /* Tunnel failed */
  PROXY_INSPECT_AUTH_RETRY  /* Retry with auth */
} proxy_inspect_result;

void Curl_http_proxy_get_destination(struct Curl_cfilter *cf,
                                     const char **phostname,
                                     uint16_t *pport, bool *pipv6_ip);

CURLcode Curl_http_proxy_create_CONNECT(struct httpreq **preq,
                                        struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        proxy_http_ver ver);
CURLcode Curl_http_proxy_create_CONNECTUDP(struct httpreq **preq,
                                           struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           proxy_http_ver ver);

/* Create CONNECT or CONNECT-UDP request */
CURLcode Curl_http_proxy_create_tunnel_request(
    struct httpreq **preq, struct Curl_cfilter *cf,
    struct Curl_easy *data, proxy_http_ver ver,
    bool udp_tunnel);

/* Inspect tunnel response for H2/H3 proxy (capsule-protocol, auth) */
struct http_resp;
CURLcode Curl_http_proxy_inspect_tunnel_response(
    struct Curl_cfilter *cf, struct Curl_easy *data,
    struct http_resp *resp, bool udp_tunnel,
    proxy_inspect_result *presult);

/* Default proxy timeout in milliseconds */
#define PROXY_TIMEOUT (3600 * 1000)

CURLcode Curl_cf_http_proxy_query(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int query, int *pres1, void *pres2);

CURLcode Curl_cf_http_proxy_insert_after(struct Curl_cfilter *cf_at,
                                         struct Curl_easy *data,
                                         bool udp_tunnel);

extern struct Curl_cftype Curl_cft_http_proxy;

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

#define IS_HTTPS_PROXY(t) (((t) == CURLPROXY_HTTPS) ||  \
                           ((t) == CURLPROXY_HTTPS2) || \
                           ((t) == CURLPROXY_HTTPS3))

#define IS_QUIC_PROXY(t) ((t) == CURLPROXY_HTTPS3)

#endif /* HEADER_CURL_HTTP_PROXY_H */
