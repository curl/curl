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

#include "urldata.h"
#include "cfilters.h"
#include "connect.h"
#include "dnscache.h"
#include "curl_trc.h"
#include "progress.h"
#include "url.h"
#include "cf-resolv.h"


struct cf_resolv_ctx {
  struct Curl_dns_entry *dns;
  CURLcode resolv_result;
  uint16_t port;
  uint8_t ip_version;
  uint8_t transport;
  BIT(started);
  BIT(announced);
  BIT(abstract_unix_socket);
  char hostname[1];
};

static struct cf_resolv_ctx *
cf_resolv_ctx_create(struct Curl_easy *data,
                     const char *hostname, uint16_t port,
                     uint8_t ip_version, uint8_t transport,
                     bool abstract_unix_socket,
                     struct Curl_dns_entry *dns)
{
  struct cf_resolv_ctx *ctx;
  size_t hlen = strlen(hostname);

  ctx = curlx_calloc(1, sizeof(*ctx) + hlen);
  if(!ctx)
    return NULL;

  ctx->port = port;
  ctx->ip_version = ip_version;
  ctx->transport = transport;
  ctx->abstract_unix_socket = abstract_unix_socket;
  ctx->dns = Curl_dns_entry_link(data, dns);
  ctx->started = !!ctx->dns;
  if(hlen)
    memcpy(ctx->hostname, hostname, hlen);

  return ctx;
}

static void cf_resolv_ctx_destroy(struct Curl_easy *data,
                                  struct cf_resolv_ctx *ctx)
{
  if(ctx) {
    Curl_dns_entry_unlink(data, &ctx->dns);
    curlx_free(ctx);
  }
}

#ifdef CURLVERBOSE
static void cf_resolv_report_addr(struct Curl_easy *data,
                                  struct dynbuf *tmp,
                                  const char *label,
                                  int ai_family,
                                  const struct Curl_addrinfo *ai)
{
  char buf[MAX_IPADR_LEN];
  const char *sep = "";
  CURLcode result;

  curlx_dyn_reset(tmp);
  for(; ai; ai = ai->ai_next) {
    if(ai->ai_family == ai_family) {
      Curl_printable_address(ai, buf, sizeof(buf));
      result = curlx_dyn_addf(tmp, "%s%s", sep, buf);
      if(result) {
        infof(data, "too many IP, cannot show");
        return;
      }
      sep = ", ";
    }
  }

  infof(data, "%s%s", label,
        (curlx_dyn_len(tmp) ? curlx_dyn_ptr(tmp) : "(none)"));
}

static void cf_resolv_report(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct Curl_dns_entry *dns)
{
  struct cf_resolv_ctx *ctx = cf->ctx;
  struct dynbuf tmp;

  if(!Curl_trc_is_verbose(data) ||
     /* ignore no name or numerical IP addresses */
     !dns->hostname[0] || Curl_host_is_ipnum(dns->hostname))
    return;

  switch(ctx->transport) {
  case TRNSPRT_UNIX:
#ifdef USE_UNIX_SOCKETS
    infof(data, "Host %s:%d resolved to UDS %s",
          dns->hostname, dns->port, Curl_conn_get_unix_path(data->conn));
#else
    DEBUGASSERT(0);
#endif
    break;
  default:
    curlx_dyn_init(&tmp, 1024);
    infof(data, "Host %s:%d was resolved.", dns->hostname, dns->port);
#ifdef CURLRES_IPV6
    cf_resolv_report_addr(data, &tmp, "IPv6: ", AF_INET6, dns->addr);
#endif
    cf_resolv_report_addr(data, &tmp, "IPv4: ", AF_INET, dns->addr);
    curlx_dyn_free(&tmp);
    break;
  }
}
#else
#define cf_resolv_report(x, y, z) Curl_nop_stmt
#endif

/*************************************************************
 * Resolve the address of the server or proxy
 *************************************************************/
static CURLcode cf_resolv_start(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct Curl_dns_entry **pdns)
{
  struct cf_resolv_ctx *ctx = cf->ctx;
  timediff_t timeout_ms = Curl_timeleft_ms(data);
  CURLcode result;

  *pdns = NULL;

#ifdef USE_UNIX_SOCKETS
  if(ctx->transport == TRNSPRT_UNIX) {
    CURL_TRC_CF(data, cf, "resolve unix socket %s", ctx->hostname);
    return Curl_resolv_unix(data, ctx->hostname,
                            (bool)cf->conn->bits.abstract_unix_socket, pdns);
  }
#endif

  /* Resolve target host right on */
  CURL_TRC_CF(data, cf, "resolve host %s:%u", ctx->hostname, ctx->port);
  result = Curl_resolv(data, ctx->hostname, ctx->port, ctx->ip_version,
                       SOCK_STREAM, timeout_ms, pdns);
  DEBUGASSERT(!result || !*pdns);
  if(!result) { /* resolved right away, either sync or from dnscache */
    DEBUGASSERT(*pdns);
    return CURLE_OK;
  }
  else if(result == CURLE_AGAIN) { /* async resolv in progress */
    return CURLE_OK;
  }
  else if(result == CURLE_OPERATION_TIMEDOUT) { /* took too long */
    failf(data, "Failed to resolve '%s' with timeout after %"
          FMT_TIMEDIFF_T " ms", ctx->hostname,
          curlx_ptimediff_ms(Curl_pgrs_now(data),
                             &data->progress.t_startsingle));
    return CURLE_OPERATION_TIMEDOUT;
  }
  else {
    DEBUGASSERT(result);
    failf(data, "Could not resolve: %s", ctx->hostname);
    return result;
  }
}

static CURLcode cf_resolv_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done)
{
  struct cf_resolv_ctx *ctx = cf->ctx;

  if(!cf->connected) {
    *done = FALSE;

    if(!ctx->started) {
      ctx->started = TRUE;
      ctx->resolv_result = cf_resolv_start(cf, data, &ctx->dns);
    }

    if(!ctx->dns && !ctx->resolv_result) {
      ctx->resolv_result = Curl_resolv_take_result(data, &ctx->dns);
      if(!ctx->dns && !ctx->resolv_result)
        CURL_TRC_CF(data, cf, "waiting for DNS resolution");
    }

    if(ctx->resolv_result) {
      CURL_TRC_CF(data, cf, "error resolving: %d", ctx->resolv_result);
      return ctx->resolv_result;
    }

    if(ctx->dns && !ctx->announced) {
      ctx->announced = TRUE;
      if(cf->sockindex == FIRSTSOCKET) {
        cf->conn->bits.dns_resolved = TRUE;
        Curl_pgrsTime(data, TIMER_NAMELOOKUP);
      }
      cf_resolv_report(cf, data, ctx->dns);
    }

    if(cf->next && !cf->next->connected) {
      CURLcode result = Curl_conn_cf_connect(cf->next, data, done);
      if(result || !*done)
        return result;
    }
  }

  *done = TRUE;
  cf->connected = TRUE;
  return CURLE_OK;
}

static void cf_resolv_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_resolv_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  cf_resolv_ctx_destroy(data, ctx);
}

static void cf_resolv_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  cf->connected = FALSE;
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static CURLcode cf_resolv_adjust_pollset(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct easy_pollset *ps)
{
  if(!cf->connected)
    return Curl_resolv_pollset(data, ps);
  return CURLE_OK;
}

struct Curl_cftype Curl_cft_resolv = {
  "RESOLVE",
  0,
  CURL_LOG_LVL_NONE,
  cf_resolv_destroy,
  cf_resolv_connect,
  cf_resolv_close,
  Curl_cf_def_shutdown,
  cf_resolv_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_resolv_create(struct Curl_cfilter **pcf,
                                 struct Curl_easy *data,
                                 const char *hostname,
                                 uint16_t port,
                                 uint8_t ip_version,
                                 uint8_t transport,
                                 bool abstract_unix_socket,
                                 struct Curl_dns_entry *dns)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_resolv_ctx *ctx;
  CURLcode result = CURLE_OK;

  /* if(!dns)
    return CURLE_FAILED_INIT; */

  (void)data;
  ctx = cf_resolv_ctx_create(data, hostname, port, ip_version, transport,
                             abstract_unix_socket, dns);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_resolv, ctx);

out:
  *pcf = result ? NULL : cf;
  if(result)
    cf_resolv_ctx_destroy(data, ctx);
  return result;
}

static CURLcode cf_resolv_conn_create(struct Curl_cfilter **pcf,
                                      struct Curl_easy *data,
                                      uint8_t transport,
                                      struct Curl_dns_entry *dns)
{
  struct connectdata *conn = data->conn;
  const char *hostname = NULL;
  uint16_t port = 0;
  uint8_t ip_version = conn->ip_version;
  bool abstract_unix_socket = FALSE;

#ifdef USE_UNIX_SOCKETS
  {
    const char *unix_path = Curl_conn_get_unix_path(conn);
    if(unix_path) {
      DEBUGASSERT(transport == TRNSPRT_UNIX);
      hostname = unix_path;
      abstract_unix_socket = (bool)conn->bits.abstract_unix_socket;
    }
  }
#endif

#ifndef CURL_DISABLE_PROXY
  if(!hostname && CONN_IS_PROXIED(conn)) {
    struct hostname *ehost;
    ehost = conn->bits.socksproxy ? &conn->socks_proxy.host :
      &conn->http_proxy.host;
    hostname = ehost->name;
    port = conn->bits.socksproxy ? conn->socks_proxy.port :
      conn->http_proxy.port;
  }
#endif
  if(!hostname) {
    struct hostname *ehost;
    ehost = conn->bits.conn_to_host ? &conn->conn_to_host : &conn->host;
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    hostname = ehost->name;
    port = conn->bits.conn_to_port ?
            conn->conn_to_port : (uint16_t)conn->remote_port;
  }

  if(!hostname) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }
  return cf_resolv_create(pcf, data, hostname, port, ip_version,
                          transport, abstract_unix_socket, dns);
}

CURLcode Curl_cf_resolv_add(struct Curl_easy *data,
                            struct connectdata *conn,
                            int sockindex,
                            uint8_t transport,
                            struct Curl_dns_entry *dns)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_resolv_conn_create(&cf, data, transport, dns);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

CURLcode Curl_cf_resolv_insert_after(struct Curl_cfilter *cf_at,
                                     struct Curl_easy *data,
                                     const char *hostname,
                                     uint16_t port,
                                     uint8_t ip_version,
                                     uint8_t transport)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_resolv_create(&cf, data, hostname, port, ip_version,
                            transport, FALSE, NULL);
  if(result)
    return result;

  Curl_conn_cf_insert_after(cf_at, cf);
  return CURLE_OK;
}

/* Get the DNS entry from the first `resolv` filter in filter chain. */
struct Curl_dns_entry *
Curl_cf_resolv_get_dns(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_resolv) {
      struct cf_resolv_ctx *ctx = cf->ctx;
      return ctx->dns;
    }
  }
  return NULL;
}

/* Get the DNS entry from the first `resolv` filter in the connection
 * filter chain at sockindex or NULL. */
struct Curl_dns_entry *
Curl_conn_resolv_get_dns(struct connectdata *conn, int sockindex)
{
  return Curl_cf_resolv_get_dns(conn->cfilter[sockindex]);
}

