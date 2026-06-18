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
#include "curl_trc.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-dns.h"
#include "cf-https-connect.h"
#include "cf-setup.h"
#include "multiif.h"
#include "progress.h"
#include "conncache.h"
#include "multihandle.h"
#include "select.h"
#include "curlx/strparse.h"

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
    result = Curl_cf_setup_add(data, conn, sockindex,
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

#ifdef CURLVERBOSE
static CURLcode conn_connect_trace(struct Curl_easy *data,
                                   struct Curl_cfilter *cf)
{
  if(Curl_trc_is_verbose(data)) {
    struct ip_quadruple ipquad;
    bool is_ipv6;
    CURLcode result;

    result = Curl_conn_cf_get_ip_info(cf, data, &is_ipv6, &ipquad);
    if(result)
      return result;

    infof(data, "Established %sconnection to %s (%s port %u) from %s port %u ",
          (cf->sockindex == SECONDARYSOCKET) ? "2nd " : "",
          CURL_CONN_HOST_DISPNAME(data->conn),
          ipquad.remote_ip, ipquad.remote_port,
          ipquad.local_ip, ipquad.local_port);
  }
  return CURLE_OK;
}
#endif

/**
 * Update connection statistics
 */
static void conn_report_connect_stats(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  if(cf) {
    struct curltime connected;
    struct curltime appconnected;

    memset(&connected, 0, sizeof(connected));
    cf->cft->query(cf, data, CF_QUERY_TIMER_CONNECT, NULL, &connected);
    if(connected.tv_sec || connected.tv_usec)
      Curl_pgrsTimeWas(data, TIMER_CONNECT, connected);

    memset(&appconnected, 0, sizeof(appconnected));
    cf->cft->query(cf, data, CF_QUERY_TIMER_APPCONNECT, NULL, &appconnected);
    if(appconnected.tv_sec || appconnected.tv_usec)
      Curl_pgrsTimeWas(data, TIMER_APPCONNECT, appconnected);
  }
}

CURLcode Curl_conn_connect(struct Curl_easy *data,
                           int sockindex,
                           bool blocking,
                           bool *done)
{
#define CF_CONN_NUM_POLLS_ON_STACK 5
  struct pollfd a_few_on_stack[CF_CONN_NUM_POLLS_ON_STACK];
  struct easy_pollset ps;
  struct curl_pollfds cpfds;
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->conn->scheme->flags & PROTOPT_NONETWORK) {
    *done = TRUE;
    return CURLE_OK;
  }

  cf = data->conn->cfilter[sockindex];
  if(!cf) {
    *done = FALSE;
    return CURLE_FAILED_INIT;
  }

  *done = (bool)cf->connected;
  if(*done)
    return CURLE_OK;

  Curl_pollset_init(&ps);
  Curl_pollfds_init(&cpfds, a_few_on_stack, CF_CONN_NUM_POLLS_ON_STACK);
  while(!*done) {
    if(Curl_conn_needs_flush(data, sockindex)) {
      DEBUGF(infof(data, "Curl_conn_connect(index=%d), flush", sockindex));
      result = Curl_conn_flush(data, sockindex);
      if(result && (result != CURLE_AGAIN))
        goto out;
    }

    result = cf->cft->do_connect(cf, data, done);
    CURL_TRC_CF(data, cf, "Curl_conn_connect(block=%d) -> %d, done=%d",
                blocking, (int)result, *done);
    if(!result && *done) {
      /* A final sanity check on connection security */
      if((data->state.origin->scheme->flags & PROTOPT_SSL) &&
         (sockindex == FIRSTSOCKET) &&
         !Curl_conn_is_ssl(data->conn, FIRSTSOCKET)) {
        DEBUGASSERT(0);
        failf(data, "transfer requires SSL, but not connected via SSL");
        result = CURLE_FAILED_INIT;
        goto out;
      }
      /* Now that the complete filter chain is connected, let all filters
       * persist information at the connection. E.g. cf-socket sets the
       * socket and ip related information. */
      Curl_conn_cntrl_update_info(data, data->conn);
      conn_report_connect_stats(cf, data);
      data->conn->keepalive = *Curl_pgrs_now(data);
      VERBOSE(result = conn_connect_trace(data, cf));
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "connected"));
      Curl_conn_remove_setup_filters(data, sockindex);
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "reduced to"));
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "Curl_conn_connect(), filter returned %d",
                  (int)result);
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "failed to connect"));
      conn_report_connect_stats(cf, data);
      goto out;
    }

    if(!blocking)
      goto out;
    else {
      /* check allowed time left */
      const timediff_t timeout_ms = Curl_timeleft_ms(data);
      curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
      int rc;

      if(timeout_ms < 0) {
        /* no need to continue if time already is up */
        failf(data, "connect timeout");
        result = CURLE_OPERATION_TIMEDOUT;
        goto out;
      }

      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), do poll");
      Curl_pollset_reset(&ps);
      Curl_pollfds_reset(&cpfds);
      /* In general, we want to send after connect, wait on that. */
      if(sockfd != CURL_SOCKET_BAD)
        result = Curl_pollset_set_out_only(data, &ps, sockfd);
      if(!result)
        result = Curl_conn_adjust_pollset(data, data->conn, &ps);
      if(result)
        goto out;
      result = Curl_pollfds_add_ps(&cpfds, &ps);
      if(result)
        goto out;

      rc = Curl_poll(cpfds.pfds, cpfds.n,
                     CURLMIN(timeout_ms, (cpfds.n ? 1000 : 10)));
      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), Curl_poll() -> %d",
                  rc);
      if(rc < 0) {
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      /* continue iterating */
    }
  }

out:
  Curl_pollset_cleanup(&ps);
  Curl_pollfds_cleanup(&cpfds);
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
