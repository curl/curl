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
#ifdef USE_HYPER
#include <hyper.h>
#endif
#include "sendf.h"
#include "http.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "cfilters.h"
#include "cf-h1-proxy.h"
#include "cf-h2-proxy.h"
#include "connect.h"
#include "curlx.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


struct cf_proxy_ctx {
  /* the protocol specific sub-filter we install during connect */
  struct Curl_cfilter *cf_protocol;
};

static CURLcode http_proxy_cf_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool blocking, bool *done)
{
  struct cf_proxy_ctx *ctx = cf->ctx;
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  DEBUGF(LOG_CF(data, cf, "connect"));
connect_sub:
  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    return result;

  *done = FALSE;
  if(!ctx->cf_protocol) {
    struct Curl_cfilter *cf_protocol = NULL;
    int alpn = Curl_conn_cf_is_ssl(cf->next)?
      cf->conn->proxy_alpn : CURL_HTTP_VERSION_1_1;

    /* First time call after the subchain connected */
    switch(alpn) {
    case CURL_HTTP_VERSION_NONE:
    case CURL_HTTP_VERSION_1_0:
    case CURL_HTTP_VERSION_1_1:
      DEBUGF(LOG_CF(data, cf, "installing subfilter for HTTP/1.1"));
      infof(data, "CONNECT tunnel: HTTP/1.%d negotiated",
            (alpn == CURL_HTTP_VERSION_1_0)? 0 : 1);
      result = Curl_cf_h1_proxy_insert_after(cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      break;
#ifdef USE_NGHTTP2
    case CURL_HTTP_VERSION_2:
      DEBUGF(LOG_CF(data, cf, "installing subfilter for HTTP/2"));
      infof(data, "CONNECT tunnel: HTTP/2 negotiated");
      result = Curl_cf_h2_proxy_insert_after(cf, data);
      if(result)
        goto out;
      cf_protocol = cf->next;
      break;
#endif
    default:
      DEBUGF(LOG_CF(data, cf, "installing subfilter for default HTTP/1.1"));
      infof(data, "CONNECT tunnel: unsupported ALPN(%d) negotiated", alpn);
      result = CURLE_COULDNT_CONNECT;
      goto out;
    }

    ctx->cf_protocol = cf_protocol;
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

void Curl_cf_http_proxy_get_host(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char **phost,
                                 const char **pdisplay_host,
                                 int *pport)
{
  (void)data;
  if(!cf->connected) {
    *phost = cf->conn->http_proxy.host.name;
    *pdisplay_host = cf->conn->http_proxy.host.dispname;
    *pport = (int)cf->conn->http_proxy.port;
  }
  else {
    cf->next->cft->get_host(cf->next, data, phost, pdisplay_host, pport);
  }
}

static void http_proxy_cf_destroy(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_proxy_ctx *ctx = cf->ctx;

  (void)data;
  DEBUGF(LOG_CF(data, cf, "destroy"));
  free(ctx);
}

static void http_proxy_cf_close(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_proxy_ctx *ctx = cf->ctx;

  DEBUGF(LOG_CF(data, cf, "close"));
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
    cf->next->cft->close(cf->next, data);
}


struct Curl_cftype Curl_cft_http_proxy = {
  "HTTP-PROXY",
  CF_TYPE_IP_CONNECT,
  0,
  http_proxy_cf_destroy,
  http_proxy_cf_connect,
  http_proxy_cf_close,
  Curl_cf_http_proxy_get_host,
  Curl_cf_def_get_select_socks,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
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
