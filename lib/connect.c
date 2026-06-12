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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* <netinet/tcp.h> may need it */
#endif
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include "urldata.h"
#include "curl_trc.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-dns.h"
#include "cf-haproxy.h"
#include "cf-https-connect.h"
#include "cf-ip-happy.h"
#include "cf-socket.h"
#include "multiif.h"
#include "curlx/strparse.h"
#include "vtls/vtls.h" /* for vtls cfilters */
#include "vquic/vquic.h" /* for QUIC cfilters */
#include "vquic/cf-capsule.h"
#include "progress.h"
#include "conncache.h"
#include "multihandle.h"
#include "http_proxy.h"
#include "socks.h"

#if !defined(CURL_DISABLE_ALTSVC) || defined(USE_HTTPSRR)

enum alpnid Curl_alpn2alpnid(const unsigned char *name, size_t len)
{
  if(len == 2) {
    if(!memcmp(name, "h1", 2))
      return ALPN_h1;
    if(!memcmp(name, "h2", 2))
      return ALPN_h2;
    if(!memcmp(name, "h3", 2))
      return ALPN_h3;
  }
  else if(len == 8) {
    if(!memcmp(name, "http/1.1", 8))
      return ALPN_h1;
  }
  return ALPN_none; /* unknown, probably rubbish input */
}

enum alpnid Curl_str2alpnid(const struct Curl_str *cstr)
{
  return Curl_alpn2alpnid((const unsigned char *)curlx_str(cstr),
                          curlx_strlen(cstr));
}

#endif

/*
 * timeleft_now_ms() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is 0, there is no timeout (ie there is
 * infinite time left). If the value is negative, the timeout time has already
 * elapsed.
 *
 * @unittest 1303
 */
UNITTEST timediff_t timeleft_now_ms(struct Curl_easy *data,
                                    const struct curltime *pnow);
UNITTEST timediff_t timeleft_now_ms(struct Curl_easy *data,
                                    const struct curltime *pnow)
{
  timediff_t timeleft_ms = 0;
  timediff_t ctimeleft_ms = 0;

  if(Curl_shutdown_started(data, FIRSTSOCKET))
    return Curl_shutdown_timeleft(data, data->conn, FIRSTSOCKET);
  else if(Curl_is_connecting(data)) {
    timediff_t ctimeout_ms = (data->set.connecttimeout > 0) ?
      data->set.connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    ctimeleft_ms = ctimeout_ms -
      curlx_ptimediff_ms(pnow, &data->progress.t_startsingle);
    if(!ctimeleft_ms)
      ctimeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
  }
  else if(!data->set.timeout || data->set.connect_only) {
    return 0; /* no timeout in place or checked, return "no limit" */
  }

  if(data->set.timeout) {
    timeleft_ms = data->set.timeout -
      curlx_ptimediff_ms(pnow, &data->progress.t_startop);
    if(!timeleft_ms)
      timeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
  }

  if(!ctimeleft_ms)
    return timeleft_ms;
  else if(!timeleft_ms)
    return ctimeleft_ms;
  return CURLMIN(ctimeleft_ms, timeleft_ms);
}

timediff_t Curl_timeleft_ms(struct Curl_easy *data)
{
  return timeleft_now_ms(data, Curl_pgrs_now(data));
}

void Curl_shutdown_start(struct Curl_easy *data, int sockindex,
                         int timeout_ms)
{
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  conn->shutdown.start[sockindex] = *Curl_pgrs_now(data);
  conn->shutdown.timeout_ms = (timeout_ms > 0) ?
    (timediff_t)timeout_ms :
    ((data->set.shutdowntimeout > 0) ?
     data->set.shutdowntimeout : DEFAULT_SHUTDOWN_TIMEOUT_MS);
  /* Set a timer, unless we operate on the admin handle */
  if(data->mid)
    Curl_expire_ex(data, conn->shutdown.timeout_ms, EXPIRE_SHUTDOWN);
  CURL_TRC_M(data, "shutdown start on%s connection",
             sockindex ? " secondary" : "");
}

timediff_t Curl_shutdown_timeleft(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex)
{
  timediff_t left_ms;

  if(!conn->shutdown.start[sockindex].tv_sec ||
     (conn->shutdown.timeout_ms <= 0))
    return 0; /* not started or no limits */

  left_ms = conn->shutdown.timeout_ms -
            curlx_ptimediff_ms(Curl_pgrs_now(data),
                               &conn->shutdown.start[sockindex]);
  return left_ms ? left_ms : -1;
}

timediff_t Curl_conn_shutdown_timeleft(struct Curl_easy *data,
                                       struct connectdata *conn)
{
  timediff_t left_ms = 0, ms;
  int i;

  for(i = 0; conn->shutdown.timeout_ms && (i < 2); ++i) {
    if(!conn->shutdown.start[i].tv_sec)
      continue;
    ms = Curl_shutdown_timeleft(data, conn, i);
    if(ms && (!left_ms || ms < left_ms))
      left_ms = ms;
  }
  return left_ms;
}

void Curl_shutdown_clear(struct Curl_easy *data, int sockindex)
{
  struct curltime *pt = &data->conn->shutdown.start[sockindex];
  memset(pt, 0, sizeof(*pt));
}

bool Curl_shutdown_started(struct Curl_easy *data, int sockindex)
{
  if(data->conn) {
    struct curltime *pt = &data->conn->shutdown.start[sockindex];
    return (pt->tv_sec > 0) || (pt->tv_usec > 0);
  }
  return FALSE;
}

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given Curl_easy.
 *
 * The returned socket will be CURL_SOCKET_BAD in case of failure!
 */
curl_socket_t Curl_getconnectinfo(struct Curl_easy *data,
                                  struct connectdata **connp)
{
  DEBUGASSERT(data);

  /* this works for an easy handle:
   * - that has been used for curl_easy_perform()
   * - that is associated with a multi handle, and whose connection
   *   was detached with CURLOPT_CONNECT_ONLY
   */
  if(data->state.lastconnect_id != -1) {
    struct connectdata *conn;

    conn = Curl_cpool_get_conn(data, data->state.lastconnect_id);
    if(!conn) {
      data->state.lastconnect_id = -1;
      return CURL_SOCKET_BAD;
    }

    if(connp)
      /* only store this if the caller cares for it */
      *connp = conn;
    return conn->sock[FIRSTSOCKET];
  }
  return CURL_SOCKET_BAD;
}

/*
 * Curl_conncontrol() marks streams or connection for closure.
 */
void Curl_conncontrol(struct connectdata *conn,
                      int ctrl /* see defines in header */
#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
                      , const char *reason
#endif
  )
{
  /* close if a connection, or a stream that is not multiplexed. */
  /* This function will be called both before and after this connection is
     associated with a transfer. */
  bool closeit, is_multiplex;
  DEBUGASSERT(conn);
#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
  (void)reason; /* useful for debugging */
#endif
  is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);
  closeit = (ctrl == CONNCTRL_CONNECTION) ||
            ((ctrl == CONNCTRL_STREAM) && !is_multiplex);
  if((ctrl == CONNCTRL_STREAM) && is_multiplex)
    ;  /* stream signal on multiplex conn never affects close state */
  else if((curl_bit)closeit != conn->bits.close) {
    conn->bits.close = closeit; /* the only place in the source code that
                                   should assign this bit */
  }
}

typedef enum {
  CF_SETUP_INIT,
  CF_SETUP_CNNCT_EYEBALLS,
  CF_SETUP_CNNCT_SOCKS,
  CF_SETUP_CNNCT_HTTP_PROXY,
  CF_SETUP_CNNCT_HAPROXY,
  CF_SETUP_CNNCT_SSL,
  CF_SETUP_DONE
} cf_setup_state;

struct cf_setup_ctx {
  cf_setup_state state;
  int ssl_mode;
  uint8_t transport;
  uint8_t retry_count;
};

#ifndef CURL_DISABLE_PROXY

static CURLcode cf_setup_add_haproxy(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(ctx->state < CF_SETUP_CNNCT_HAPROXY) {
    if(data->set.haproxyprotocol) {
      if(ctx->transport == TRNSPRT_QUIC) {
        failf(data, "haproxy protocol does not support QUIC");
        return CURLE_UNSUPPORTED_PROTOCOL;
      }
      result = Curl_cf_haproxy_insert_after(cf, data);
      if(result) {
        CURL_TRC_CF(data, cf, "adding HAPROXY filter failed -> %d",
                    (int)result);
        return result;
      }
      CURL_TRC_CF(data, cf, "added HAPROXY filter");
    }
    ctx->state = CF_SETUP_CNNCT_HAPROXY;
  }
  return result;
}

static CURLcode cf_setup_add_socks(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  if(ctx->state < CF_SETUP_CNNCT_SOCKS && cf->conn->socks_proxy.peer) {
    /* Add a SOCKS proxy to go through `first_peer` to `second_peer`*/
    struct Curl_peer *second_peer;

    if(cf->conn->http_proxy.peer)
      second_peer = cf->conn->http_proxy.peer;
    else
      second_peer = Curl_conn_get_destination(cf->conn, cf->sockindex);
    if(!second_peer)
      return CURLE_FAILED_INIT;

    result = Curl_cf_socks_proxy_insert_after(
      cf, data, second_peer, cf->conn->ip_version,
      cf->conn->socks_proxy.proxytype,
      cf->conn->socks_proxy.creds);
    if(result) {
      CURL_TRC_CF(data, cf, "adding SOCKS filter failed -> %d", (int)result);
      return result;
    }

    CURL_TRC_CF(data, cf, "added SOCKS filter to %s:%u",
                second_peer->hostname, second_peer->port);
    ctx->state = CF_SETUP_CNNCT_SOCKS;
  }
  return result;
}

#ifndef CURL_DISABLE_HTTP
static CURLcode cf_setup_add_http_proxy(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(ctx->state < CF_SETUP_CNNCT_HTTP_PROXY &&
     cf->conn->http_proxy.peer && !cf->conn->bits.origin_is_proxy) {
    struct Curl_peer *peer = cf->conn->http_proxy.peer;
    struct Curl_peer *tunnel_peer =
      Curl_conn_get_destination(cf->conn, cf->sockindex);

#ifdef USE_SSL
    if(CURL_PROXY_IS_HTTPS(cf->conn->http_proxy.proxytype) &&
       !Curl_conn_is_ssl(cf->conn, cf->sockindex)) {
      result = Curl_cf_ssl_proxy_insert_after(
        cf, data, cf->conn->http_proxy.peer);
      if(result) {
        CURL_TRC_CF(data, cf, "adding SSL filter for HTTP proxy failed -> %d",
                    (int)result);
        return result;
      }
      CURL_TRC_CF(data, cf, "added SSL filter for HTTP proxy");
    }
#endif /* USE_SSL */

    result = Curl_cf_http_proxy_insert_after(
      cf, data, peer, tunnel_peer,
      ctx->transport, cf->conn->http_proxy.proxytype);
    if(result) {
      CURL_TRC_CF(data, cf, "adding HTTP proxy tunnel filter failed -> %d",
                  (int)result);
      return result;
    }
    CURL_TRC_CF(data, cf, "added HTTP proxy tunnel filter");
    ctx->state = CF_SETUP_CNNCT_HTTP_PROXY;
  }
  return result;
}
#endif /* !CURL_DISABLE_HTTP */
#endif /* CURL_DISABLE_PROXY */

/* Get the origin curl connects its socket to.
 * Can be origin or the first proxy. */
static struct Curl_peer *conn_get_first_origin(struct connectdata *conn,
                                             int sockindex)
{
#ifndef CURL_DISABLE_PROXY
  if(conn->socks_proxy.peer)
    return conn->socks_proxy.peer;
  if(conn->http_proxy.peer)
    return conn->http_proxy.peer;
#endif
  return (sockindex == SECONDARYSOCKET) ? conn->origin2 : conn->origin;
}

static CURLcode cf_setup_add_ip_happy(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(ctx->state < CF_SETUP_CNNCT_EYEBALLS) {
    /* What is the first hop we directly connect to and what transport
     * do we use for it? Only on the first hop we can do Happy Eyeballs.
     * first_origin and first_peer differ on --connect-to. */
    struct Curl_peer *first_origin =
      conn_get_first_origin(cf->conn, cf->sockindex);
    struct Curl_peer *first_peer =
      Curl_conn_get_first_peer(cf->conn, cf->sockindex);
    struct Curl_peer *tunnel_peer = NULL;
    uint8_t first_transport = ctx->transport;

    if(!first_peer)
      return CURLE_FAILED_INIT;

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
    if(cf->conn->http_proxy.peer && !cf->conn->bits.origin_is_proxy) {
      first_transport =
        Curl_http_proxy_transport(cf->conn->http_proxy.proxytype);
      tunnel_peer = Curl_conn_get_destination(cf->conn, cf->sockindex);
      if((first_transport == TRNSPRT_QUIC) && cf->conn->socks_proxy.peer) {
        failf(data, "HTTP/3 proxy not possible via SOCKS");
        return CURLE_UNSUPPORTED_PROTOCOL;
      }
    }
#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

    result = cf_ip_happy_insert_after(cf, data, first_origin, first_peer,
                                      first_transport,
                                      tunnel_peer, ctx->transport);
    if(result) {
      CURL_TRC_CF(data, cf, "adding happy eyeballs failed -> %d", (int)result);
      return result;
    }

    if(tunnel_peer && (first_transport == TRNSPRT_QUIC)) {
      CURL_TRC_CF(data, cf, "happy eyeballing to HTTP/3 proxy %s:%u",
                  first_peer->hostname, first_peer->port);
      ctx->state = CF_SETUP_CNNCT_HTTP_PROXY;
    }
    else {
      CURL_TRC_CF(data, cf, "happy eyeballing to %s %s:%u",
                  tunnel_peer ? "proxy" : "origin",
                  first_peer->hostname, first_peer->port);
      ctx->state = CF_SETUP_CNNCT_EYEBALLS;
    }
  }
  return result;
}

static CURLcode cf_setup_add_origin_filters(struct Curl_cfilter *cf,
                                            struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)data; /* not used in all builds */
  if(ctx->state < CF_SETUP_CNNCT_SSL) {
#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3) && \
    !defined(CURL_DISABLE_PROXY)

    /* Wanting QUIC with a HTTP tunneling filter, we now need to add
     * the QUIC filter on top. Without tunneling, this has already
     * happened in the Happy Eyeball filter. */
    if(ctx->transport == TRNSPRT_QUIC &&
       cf->conn->http_proxy.peer && !cf->conn->bits.origin_is_proxy) {
      struct Curl_peer *origin = Curl_conn_get_origin(cf->conn, cf->sockindex);
      struct Curl_peer *peer =
        Curl_conn_get_destination(cf->conn, cf->sockindex);

      result = Curl_cf_capsule_insert_after(cf, data);
      if(result) {
        CURL_TRC_CF(data, cf, "adding capsule filter failed -> %d",
                    (int)result);
        return result;
      }
      result = Curl_cf_quic_insert_after(cf, origin, peer);
      if(result) {
        CURL_TRC_CF(data, cf, "adding QUIC filter failed -> %d", (int)result);
        return result;
      }
      CURL_TRC_CF(data, cf, "added QUIC filter for origin");
    }
    else
#endif /* !CURL_DISABLE_HTTP && USE_HTTP3 && CURL_DISABLE_PROXY */
#ifdef USE_SSL
    if((ctx->ssl_mode == CURL_CF_SSL_ENABLE ||
        (ctx->ssl_mode != CURL_CF_SSL_DISABLE &&
         cf->conn->scheme->flags & PROTOPT_SSL)) && /* we want SSL */
       !Curl_conn_is_ssl(cf->conn, cf->sockindex)) { /* it is missing */

#ifndef CURL_DISABLE_PROXY
      if(cf->conn->bits.origin_is_proxy) {
        result = Curl_cf_ssl_proxy_insert_after(cf, data, cf->conn->origin);
      }
      else
#endif
      {
        /* Another FTP quirk: when adding SSL verification, to a DATA
         * connection, always verify against the control's origin */
        struct Curl_peer *origin = Curl_conn_get_origin(cf->conn, FIRSTSOCKET);
        struct Curl_peer *peer =
          Curl_conn_get_destination(cf->conn, cf->sockindex);
        result = Curl_cf_ssl_insert_after(cf, data, origin, peer);
      }
      if(result) {
        CURL_TRC_CF(data, cf, "adding SSL filter for origin failed -> %d",
                    (int)result);
        return result;
      }
      CURL_TRC_CF(data, cf, "added SSL filter for origin");
    }
#endif /* USE_SSL */
    ctx->state = CF_SETUP_CNNCT_SSL;
  }
  return result;
}

static CURLcode cf_setup_connect_steps(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* connect current sub-chain */
connect_sub_chain:
  VERBOSE(Curl_conn_trc_filters(data, cf->sockindex, "cf_setup_connect"));

  if(cf->next && !cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  result = cf_setup_add_ip_happy(cf, data);
  if(result)
    return result;
  if(!cf->next || !cf->next->connected)
    goto connect_sub_chain;

#ifndef CURL_DISABLE_PROXY
  result = cf_setup_add_socks(cf, data);
  if(result)
    return result;
  if(!cf->next || !cf->next->connected)
    goto connect_sub_chain;

#ifndef CURL_DISABLE_HTTP
  result = cf_setup_add_http_proxy(cf, data);
  if(result)
    return result;
  if(!cf->next || !cf->next->connected)
    goto connect_sub_chain;
#endif /* !CURL_DISABLE_HTTP */

  result = cf_setup_add_haproxy(cf, data);
  if(result)
    return result;
  if(!cf->next || !cf->next->connected)
    goto connect_sub_chain;
#endif /* !CURL_DISABLE_PROXY */

  result = cf_setup_add_origin_filters(cf, data);
  if(result)
    return result;
  if(!cf->next || !cf->next->connected)
    goto connect_sub_chain;

  ctx->state = CF_SETUP_DONE;
  cf->connected = TRUE;
  *done = TRUE;
  return CURLE_OK;
}

static CURLcode cf_setup_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result;

  /* In some situations, a server/proxy may close the connection and
   * we need to connect again (HTTP/1.x proxy auth, for example).
   * We used to close the filters and reuse them for another attempt,
   * however that complicates filter code and it is simpler to tear them
   * all down and start over. */
retry:
  result = cf_setup_connect_steps(cf, data, done);

  if(result == CURLE_AGAIN) {
    ++ctx->retry_count;
    if(ctx->retry_count > 5) /* arbitrary limit, better just timeout? */
      return CURLE_COULDNT_CONNECT;

    CURL_TRC_CF(data, cf, "retrying connect, %d. time", ctx->retry_count);
    Curl_conn_cf_discard_chain(&cf->next, data);
    ctx->state = CF_SETUP_INIT;
    goto retry;
  }
  return result;
}

static void cf_setup_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  curlx_safefree(ctx);
}

struct Curl_cftype Curl_cft_setup = {
  "SETUP",
  CF_TYPE_SETUP,
  CURL_LOG_LVL_NONE,
  cf_setup_destroy,
  cf_setup_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_setup_create(struct Curl_cfilter **pcf,
                                struct Curl_easy *data,
                                uint8_t transport,
                                int ssl_mode)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_setup_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->state = CF_SETUP_INIT;
  ctx->ssl_mode = ssl_mode;
  ctx->transport = transport;

  result = Curl_cf_create(&cf, &Curl_cft_setup, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  *pcf = result ? NULL : cf;
  if(ctx) {
    curlx_free(ctx);
  }
  return result;
}

static CURLcode cf_setup_add(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             uint8_t transport,
                             int ssl_mode)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_setup_create(&cf, data, transport, ssl_mode);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

CURLcode Curl_cf_setup_insert_after(struct Curl_cfilter *cf_at,
                                    struct Curl_easy *data,
                                    uint8_t transport,
                                    int ssl_mode)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);
  result = cf_setup_create(&cf, data, transport, ssl_mode);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);
out:
  return result;
}

CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         int ssl_mode)
{
  CURLcode result = CURLE_OK;
  struct Curl_peer *peer = Curl_conn_get_first_peer(conn, sockindex);
  uint8_t dns_queries;

  DEBUGASSERT(data);
  DEBUGASSERT(conn->scheme);
  DEBUGASSERT(!conn->cfilter[sockindex]);

  if(!peer)
    return CURLE_FAILED_INIT;

#ifndef CURL_DISABLE_HTTP
  if(!conn->cfilter[sockindex] &&
     conn->scheme->protocol == CURLPROTO_HTTPS) {
    DEBUGASSERT(ssl_mode != CURL_CF_SSL_DISABLE);
    result = Curl_cf_https_setup(data, conn, sockindex);
    if(result)
      goto out;
  }
#endif /* !CURL_DISABLE_HTTP */

  /* Still no cfilter set, apply default. */
  if(!conn->cfilter[sockindex]) {
    result = cf_setup_add(data, conn, sockindex,
                          conn->transport_wanted, ssl_mode);
    if(result)
      goto out;
  }

  dns_queries = Curl_resolv_dns_queries(data, conn->ip_version);
#ifdef USE_HTTPSRR
  if(sockindex == FIRSTSOCKET)
    dns_queries |= CURL_DNSQ_HTTPS;
#endif
  result = Curl_cf_dns_add(data, conn, sockindex, peer, dns_queries,
                           conn->transport_wanted);
  DEBUGASSERT(conn->cfilter[sockindex]);
out:
  return result;
}

void Curl_conn_set_multiplex(struct connectdata *conn)
{
  if(!conn->bits.multiplex) {
    conn->bits.multiplex = TRUE;
    if(conn->attached_multi) {
      Curl_multi_connchanged(conn->attached_multi);
    }
  }
}

struct Curl_peer *Curl_conn_get_origin(struct connectdata *conn,
                                       int sockindex)
{
  return (sockindex == SECONDARYSOCKET) ?
    conn->origin2 : conn->origin;
}

struct Curl_peer *Curl_conn_get_destination(struct connectdata *conn,
                                            int sockindex)
{
  return (sockindex == SECONDARYSOCKET) ?
    (conn->via_peer2 ? conn->via_peer2 : conn->origin2) :
    (conn->via_peer ? conn->via_peer : conn->origin);
}

struct Curl_peer *Curl_conn_get_first_peer(struct connectdata *conn,
                                           int sockindex)
{
#ifndef CURL_DISABLE_PROXY
  if(conn->socks_proxy.peer)
    return conn->socks_proxy.peer;
  if(conn->http_proxy.peer)
    return conn->http_proxy.peer;
#endif
  return (sockindex == SECONDARYSOCKET) ?
    (conn->via_peer2 ? conn->via_peer2 : conn->origin2) :
    (conn->via_peer ? conn->via_peer : conn->origin);
}
