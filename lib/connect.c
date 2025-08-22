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
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-haproxy.h"
#include "cf-https-connect.h"
#include "cf-ip-happy.h"
#include "cf-socket.h"
#include "select.h"
#include "url.h" /* for Curl_safefree() */
#include "multiif.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "curlx/inet_ntop.h"
#include "curlx/inet_pton.h"
#include "vtls/vtls.h" /* for vtsl cfilters */
#include "progress.h"
#include "curlx/warnless.h"
#include "conncache.h"
#include "multihandle.h"
#include "share.h"
#include "http_proxy.h"
#include "socks.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if !defined(CURL_DISABLE_ALTSVC) || defined(USE_HTTPSRR)

enum alpnid Curl_alpn2alpnid(const char *name, size_t len)
{
  if(len == 2) {
    if(curl_strnequal(name, "h1", 2))
      return ALPN_h1;
    if(curl_strnequal(name, "h2", 2))
      return ALPN_h2;
    if(curl_strnequal(name, "h3", 2))
      return ALPN_h3;
  }
  else if(len == 8) {
    if(curl_strnequal(name, "http/1.1", 8))
      return ALPN_h1;
  }
  return ALPN_none; /* unknown, probably rubbish input */
}

#endif

/*
 * Curl_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is 0, there is no timeout (ie there is
 * infinite time left). If the value is negative, the timeout time has already
 * elapsed.
 * @param data the transfer to check on
 * @param nowp timestamp to use for calculation, NULL to use curlx_now()
 * @param duringconnect TRUE iff connect timeout is also taken into account.
 * @unittest: 1303
 */
timediff_t Curl_timeleft(struct Curl_easy *data,
                         struct curltime *nowp,
                         bool duringconnect)
{
  timediff_t timeleft_ms = 0;
  timediff_t ctimeleft_ms = 0;
  struct curltime now;

  /* The duration of a connect and the total transfer are calculated from two
     different time-stamps. It can end up with the total timeout being reached
     before the connect timeout expires and we must acknowledge whichever
     timeout that is reached first. The total timeout is set per entire
     operation, while the connect timeout is set per connect. */
  if(data->set.timeout <= 0 && !duringconnect)
    return 0; /* no timeout in place or checked, return "no limit" */

  if(!nowp) {
    now = curlx_now();
    nowp = &now;
  }

  if(data->set.timeout > 0) {
    timeleft_ms = data->set.timeout -
                  curlx_timediff(*nowp, data->progress.t_startop);
    if(!timeleft_ms)
      timeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
    if(!duringconnect)
      return timeleft_ms; /* no connect check, this is it */
  }

  if(duringconnect) {
    timediff_t ctimeout_ms = (data->set.connecttimeout > 0) ?
      data->set.connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    ctimeleft_ms = ctimeout_ms -
                   curlx_timediff(*nowp, data->progress.t_startsingle);
    if(!ctimeleft_ms)
      ctimeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
    if(!timeleft_ms)
      return ctimeleft_ms; /* no general timeout, this is it */
  }
  /* return minimal time left or max amount already expired */
  return (ctimeleft_ms < timeleft_ms) ? ctimeleft_ms : timeleft_ms;
}

void Curl_shutdown_start(struct Curl_easy *data, int sockindex,
                         int timeout_ms, struct curltime *nowp)
{
  struct curltime now;

  DEBUGASSERT(data->conn);
  if(!nowp) {
    now = curlx_now();
    nowp = &now;
  }
  data->conn->shutdown.start[sockindex] = *nowp;
  data->conn->shutdown.timeout_ms = (timeout_ms > 0) ?
    (timediff_t)timeout_ms :
    ((data->set.shutdowntimeout > 0) ?
     data->set.shutdowntimeout : DEFAULT_SHUTDOWN_TIMEOUT_MS);
  /* Set a timer, unless we operate on the admin handle */
  if(data->mid && (data->conn->shutdown.timeout_ms > 0))
    Curl_expire_ex(data, nowp, data->conn->shutdown.timeout_ms,
                   EXPIRE_SHUTDOWN);
}

timediff_t Curl_shutdown_timeleft(struct connectdata *conn, int sockindex,
                                  struct curltime *nowp)
{
  struct curltime now;
  timediff_t left_ms;

  if(!conn->shutdown.start[sockindex].tv_sec ||
     (conn->shutdown.timeout_ms <= 0))
    return 0; /* not started or no limits */

  if(!nowp) {
    now = curlx_now();
    nowp = &now;
  }
  left_ms = conn->shutdown.timeout_ms -
            curlx_timediff(*nowp, conn->shutdown.start[sockindex]);
  return left_ms ? left_ms : -1;
}

timediff_t Curl_conn_shutdown_timeleft(struct connectdata *conn,
                                       struct curltime *nowp)
{
  timediff_t left_ms = 0, ms;
  struct curltime now;
  int i;

  for(i = 0; conn->shutdown.timeout_ms && (i < 2); ++i) {
    if(!conn->shutdown.start[i].tv_sec)
      continue;
    if(!nowp) {
      now = curlx_now();
      nowp = &now;
    }
    ms = Curl_shutdown_timeleft(conn, i, nowp);
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
  struct curltime *pt = &data->conn->shutdown.start[sockindex];
  return (pt->tv_sec > 0) || (pt->tv_usec > 0);
}

/* retrieves ip address and port from a sockaddr structure. note it calls
   curlx_inet_ntop which sets errno on fail, not SOCKERRNO. */
bool Curl_addr2string(struct sockaddr *sa, curl_socklen_t salen,
                      char *addr, int *port)
{
  struct sockaddr_in *si = NULL;
#ifdef USE_IPV6
  struct sockaddr_in6 *si6 = NULL;
#endif
#if (defined(HAVE_SYS_UN_H) || defined(WIN32_SOCKADDR_UN)) && defined(AF_UNIX)
  struct sockaddr_un *su = NULL;
#else
  (void)salen;
#endif

  switch(sa->sa_family) {
    case AF_INET:
      si = (struct sockaddr_in *)(void *) sa;
      if(curlx_inet_ntop(sa->sa_family, &si->sin_addr, addr, MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si->sin_port);
        *port = us_port;
        return TRUE;
      }
      break;
#ifdef USE_IPV6
    case AF_INET6:
      si6 = (struct sockaddr_in6 *)(void *) sa;
      if(curlx_inet_ntop(sa->sa_family, &si6->sin6_addr, addr,
                         MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si6->sin6_port);
        *port = us_port;
        return TRUE;
      }
      break;
#endif
#if (defined(HAVE_SYS_UN_H) || defined(WIN32_SOCKADDR_UN)) && defined(AF_UNIX)
    case AF_UNIX:
      if(salen > (curl_socklen_t)sizeof(CURL_SA_FAMILY_T)) {
        su = (struct sockaddr_un*)sa;
        msnprintf(addr, MAX_IPADR_LEN, "%s", su->sun_path);
      }
      else
        addr[0] = 0; /* socket with no name */
      *port = 0;
      return TRUE;
#endif
    default:
      break;
  }

  addr[0] = '\0';
  *port = 0;
  CURL_SETERRNO(SOCKEAFNOSUPPORT);
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
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
                      , const char *reason
#endif
  )
{
  /* close if a connection, or a stream that is not multiplexed. */
  /* This function will be called both before and after this connection is
     associated with a transfer. */
  bool closeit, is_multiplex;
  DEBUGASSERT(conn);
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void)reason; /* useful for debugging */
#endif
  is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);
  closeit = (ctrl == CONNCTRL_CONNECTION) ||
    ((ctrl == CONNCTRL_STREAM) && !is_multiplex);
  if((ctrl == CONNCTRL_STREAM) && is_multiplex)
    ;  /* stream signal on multiplex conn never affects close state */
  else if((bit)closeit != conn->bits.close) {
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
  int transport;
};

static CURLcode cf_setup_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct Curl_dns_entry *dns = data->state.dns[cf->sockindex];

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* connect current sub-chain */
connect_sub_chain:
  if(!dns)
    return CURLE_FAILED_INIT;

  if(cf->next && !cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  if(ctx->state < CF_SETUP_CNNCT_EYEBALLS) {
    result = cf_ip_happy_insert_after(cf, data, ctx->transport);
    if(result)
      return result;
    ctx->state = CF_SETUP_CNNCT_EYEBALLS;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  /* sub-chain connected, do we need to add more? */
#ifndef CURL_DISABLE_PROXY
  if(ctx->state < CF_SETUP_CNNCT_SOCKS && cf->conn->bits.socksproxy) {
    result = Curl_cf_socks_proxy_insert_after(cf, data);
    if(result)
      return result;
    ctx->state = CF_SETUP_CNNCT_SOCKS;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  if(ctx->state < CF_SETUP_CNNCT_HTTP_PROXY && cf->conn->bits.httpproxy) {
#ifdef USE_SSL
    if(IS_HTTPS_PROXY(cf->conn->http_proxy.proxytype)
       && !Curl_conn_is_ssl(cf->conn, cf->sockindex)) {
      result = Curl_cf_ssl_proxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* USE_SSL */

#ifndef CURL_DISABLE_HTTP
    if(cf->conn->bits.tunnel_proxy) {
      result = Curl_cf_http_proxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* !CURL_DISABLE_HTTP */
    ctx->state = CF_SETUP_CNNCT_HTTP_PROXY;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }
#endif /* !CURL_DISABLE_PROXY */

  if(ctx->state < CF_SETUP_CNNCT_HAPROXY) {
#ifndef CURL_DISABLE_PROXY
    if(data->set.haproxyprotocol) {
      if(Curl_conn_is_ssl(cf->conn, cf->sockindex)) {
        failf(data, "haproxy protocol not support with SSL "
              "encryption in place (QUIC?)");
        return CURLE_UNSUPPORTED_PROTOCOL;
      }
      result = Curl_cf_haproxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* !CURL_DISABLE_PROXY */
    ctx->state = CF_SETUP_CNNCT_HAPROXY;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  if(ctx->state < CF_SETUP_CNNCT_SSL) {
#ifdef USE_SSL
    if((ctx->ssl_mode == CURL_CF_SSL_ENABLE
        || (ctx->ssl_mode != CURL_CF_SSL_DISABLE
           && cf->conn->handler->flags & PROTOPT_SSL)) /* we want SSL */
       && !Curl_conn_is_ssl(cf->conn, cf->sockindex)) { /* it is missing */
      result = Curl_cf_ssl_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* USE_SSL */
    ctx->state = CF_SETUP_CNNCT_SSL;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  ctx->state = CF_SETUP_DONE;
  cf->connected = TRUE;
  *done = TRUE;
  return CURLE_OK;
}

static void cf_setup_close(struct Curl_cfilter *cf,
                           struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf->connected = FALSE;
  ctx->state = CF_SETUP_INIT;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static void cf_setup_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;

  (void)data;
  CURL_TRC_CF(data, cf, "destroy");
  Curl_safefree(ctx);
}


struct Curl_cftype Curl_cft_setup = {
  "SETUP",
  0,
  CURL_LOG_LVL_NONE,
  cf_setup_destroy,
  cf_setup_connect,
  cf_setup_close,
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
                                int transport,
                                int ssl_mode)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_setup_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
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
    free(ctx);
  }
  return result;
}

static CURLcode cf_setup_add(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             int transport,
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
                                    int transport,
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
                         struct Curl_dns_entry *dns,
                         int ssl_mode)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(conn->handler);
  DEBUGASSERT(dns);

  Curl_resolv_unlink(data, &data->state.dns[sockindex]);
  data->state.dns[sockindex] = dns;

#ifndef CURL_DISABLE_HTTP
  if(!conn->cfilter[sockindex] &&
     conn->handler->protocol == CURLPROTO_HTTPS) {
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

  DEBUGASSERT(conn->cfilter[sockindex]);
out:
  if(result)
    Curl_resolv_unlink(data, &data->state.dns[sockindex]);
  return result;
}
