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
#include "curl_addrinfo.h"
#include "cfilters.h"
#include "connect.h"
#include "dnscache.h"
#include "httpsrr.h"
#include "curl_trc.h"
#include "progress.h"
#include "url.h"
#include "cf-dns.h"


struct cf_dns_ctx {
  struct Curl_dns_entry *dns;
  CURLcode resolv_result;
  uint32_t resolv_id;
  uint16_t port;
  uint8_t dns_queries;
  uint8_t transport;
  BIT(started);
  BIT(announced);
  BIT(abstract_unix_socket);
  BIT(complete_resolve);
  BIT(for_proxy);
  char hostname[1];
};

static struct cf_dns_ctx *cf_dns_ctx_create(struct Curl_easy *data,
                                            uint8_t dns_queries,
                                            const char *hostname,
                                            uint16_t port, uint8_t transport,
                                            bool abstract_unix_socket,
                                            bool for_proxy,
                                            bool complete_resolve,
                                            struct Curl_dns_entry *dns)
{
  struct cf_dns_ctx *ctx;
  size_t hlen = strlen(hostname);

  ctx = curlx_calloc(1, sizeof(*ctx) + hlen);
  if(!ctx)
    return NULL;

  ctx->port = port;
  ctx->dns_queries = dns_queries;
  ctx->transport = transport;
  ctx->abstract_unix_socket = abstract_unix_socket;
  ctx->for_proxy = for_proxy;
  ctx->complete_resolve = complete_resolve;
  ctx->dns = Curl_dns_entry_link(data, dns);
  ctx->started = !!ctx->dns;
  if(hlen)
    memcpy(ctx->hostname, hostname, hlen);

  CURL_TRC_DNS(data, "created DNS filter for %s:%u, transport=%x, queries=%x",
               ctx->hostname, ctx->port, ctx->transport, ctx->dns_queries);
  return ctx;
}

static void cf_dns_ctx_destroy(struct Curl_easy *data,
                               struct cf_dns_ctx *ctx)
{
  if(ctx) {
    Curl_dns_entry_unlink(data, &ctx->dns);
    curlx_free(ctx);
  }
}

#ifdef CURLVERBOSE
static void cf_dns_report_addr(struct Curl_easy *data,
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

static void cf_dns_report(struct Curl_cfilter *cf,
                          struct Curl_easy *data,
                          struct Curl_dns_entry *dns)
{
  struct cf_dns_ctx *ctx = cf->ctx;
  struct dynbuf tmp;

  if(!Curl_trc_is_verbose(data) ||
     /* ignore no name or numerical IP addresses */
     !dns->hostname[0] || Curl_host_is_ipnum(dns->hostname))
    return;

  switch(ctx->transport) {
  case TRNSPRT_UNIX:
#ifdef USE_UNIX_SOCKETS
    CURL_TRC_CF(data, cf, "resolved unix domain %s",
                Curl_conn_get_unix_path(data->conn));
#else
    DEBUGASSERT(0);
#endif
    break;
  default:
    curlx_dyn_init(&tmp, 1024);
    infof(data, "Host %s:%u was resolved.", dns->hostname, dns->port);
#ifdef CURLRES_IPV6
    cf_dns_report_addr(data, &tmp, "IPv6: ", AF_INET6, dns->addr);
#endif
    cf_dns_report_addr(data, &tmp, "IPv4: ", AF_INET, dns->addr);
#ifdef USE_HTTPSRR
    if(!dns->hinfo)
      infof(data, "HTTPS-RR: -");
    else if(!Curl_httpsrr_applicable(data, dns->hinfo))
      infof(data, "HTTPS-RR: not applicable");
    else {
      CURLcode result = Curl_httpsrr_print(&tmp, dns->hinfo);
      if(!result)
        infof(data, "HTTPS-RR: %s", curlx_dyn_ptr(&tmp));
      else
        infof(data, "Error printing HTTPS-RR information");
    }
#endif
    curlx_dyn_free(&tmp);
    break;
  }
}
#else
#define cf_dns_report(x, y, z) Curl_nop_stmt
#endif

/*************************************************************
 * Resolve the address of the server or proxy
 *************************************************************/
static CURLcode cf_dns_start(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct Curl_dns_entry **pdns)
{
  struct cf_dns_ctx *ctx = cf->ctx;
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
  CURL_TRC_CF(data, cf, "cf_dns_start host %s:%u", ctx->hostname, ctx->port);
  if(Curl_is_ipv4addr(ctx->hostname))
    ctx->dns_queries |= CURL_DNSQ_A;
#ifdef USE_IPV6
  else if(Curl_is_ipaddr(ctx->hostname)) /* not ipv4, must be ipv6 then */
    ctx->dns_queries |= CURL_DNSQ_AAAA;
#endif
  result = Curl_resolv(data, ctx->dns_queries,
                       ctx->hostname, ctx->port, ctx->transport,
                       (bool)ctx->for_proxy, timeout_ms,
                       &ctx->resolv_id, pdns);
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

#define CURL_HEV3_RESOLVE_DELAY_MS    50

static bool cf_dns_ready_to_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_dns_ctx *ctx = cf->ctx;

  if(ctx->resolv_result)
    return TRUE;
  else if(ctx->dns)
    return TRUE;
#ifdef USE_CURL_ASYNC
  else {
    /* We want AAAA answer as we prefer ipv6. If a sub-filter desires
    * HTTPS-RR, we check for that query as well. */
    uint8_t wanted_answers = CURL_DNSQ_AAAA;
    if(Curl_conn_cf_wants_httpsrr(cf, data))
      wanted_answers |= CURL_DNSQ_HTTPS;

    /* Note: if a query was never started, it is considered to have
     * an answer (e.g. a negative one). */
    if(Curl_resolv_has_answers(data, ctx->resolv_id, wanted_answers))
      return TRUE;
    /* If the wanted answers are not available after a delay,
     * we let the connect attempts start anyway. */
    return Curl_resolv_elapsed_ms(data, ctx->resolv_id) >=
           CURL_HEV3_RESOLVE_DELAY_MS;
  }
#else
  (void)data;
  DEBUGASSERT(0); /* We should not come here */
  return FALSE;
#endif /* USE_CURL_ASYNC */
}

static CURLcode cf_dns_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *done)
{
  struct cf_dns_ctx *ctx = cf->ctx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  if(!ctx->started) {
    ctx->started = TRUE;
    ctx->resolv_result = cf_dns_start(cf, data, &ctx->dns);
  }

  if(!ctx->dns && !ctx->resolv_result) {
    ctx->resolv_result =
      Curl_resolv_take_result(data, ctx->resolv_id, &ctx->dns);
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
    cf_dns_report(cf, data, ctx->dns);
  }

  if(!cf_dns_ready_to_connect(cf, data)) {
    return CURLE_OK;
  }

  if(cf->next && !cf->next->connected) {
    bool sub_done;
    CURLcode result = Curl_conn_cf_connect(cf->next, data, &sub_done);
    if(result || !sub_done)
      return result;
    DEBUGASSERT(sub_done);
  }

  /* sub filter chain is connected */
  CURL_TRC_CF(data, cf, "connected filter chain below");
  if(ctx->complete_resolve && !ctx->dns && !ctx->resolv_result) {
    /* This filter only connects when it has resolved everything. */
    CURL_TRC_CF(data, cf, "delay connect until resolve complete");
    return CURLE_OK;
  }
  *done = TRUE;
  cf->connected = TRUE;
  Curl_resolv_destroy(data, ctx->resolv_id);
  return CURLE_OK;
}

static void cf_dns_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_dns_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  cf_dns_ctx_destroy(data, ctx);
}

static void cf_dns_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  cf->connected = FALSE;
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static CURLcode cf_dns_adjust_pollset(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
#ifdef USE_CURL_ASYNC
  if(!cf->connected)
    return Curl_resolv_pollset(data, ps);
#else
  (void)cf;
  (void)data;
  (void)ps;
#endif
  return CURLE_OK;
}

static CURLcode cf_dns_cntrl(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             int event, int arg1, void *arg2)
{
  struct cf_dns_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_DONE:
    if(ctx->dns) {
      /* Should only come here when the connect attempt failed and
       * `data` is giving up on it. On a successful connect, we already
       * unlinked the DNS entry. */
      Curl_dns_entry_unlink(data, &ctx->dns);
    }
    break;
  default:
    break;
  }
  return result;
}

struct Curl_cftype Curl_cft_dns = {
  "DNS",
  CF_TYPE_SETUP,
  CURL_LOG_LVL_NONE,
  cf_dns_destroy,
  cf_dns_connect,
  cf_dns_close,
  Curl_cf_def_shutdown,
  cf_dns_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  cf_dns_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_dns_create(struct Curl_cfilter **pcf,
                              struct Curl_easy *data,
                              uint8_t dns_queries,
                              const char *hostname,
                              uint16_t port,
                              uint8_t transport,
                              bool abstract_unix_socket,
                              bool for_proxy,
                              bool complete_resolve,
                              struct Curl_dns_entry *dns)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_dns_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = cf_dns_ctx_create(data, dns_queries, hostname, port, transport,
                          abstract_unix_socket, for_proxy,
                          complete_resolve, dns);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_dns, ctx);

out:
  *pcf = result ? NULL : cf;
  if(result)
    cf_dns_ctx_destroy(data, ctx);
  return result;
}

/* Create a "resolv" filter for the transfer's connection. Figures
 * out the hostname/path and port where to connect to. */
static CURLcode cf_dns_conn_create(struct Curl_cfilter **pcf,
                                   struct Curl_easy *data,
                                   uint8_t dns_queries,
                                   uint8_t transport,
                                   bool complete_resolve,
                                   struct Curl_dns_entry *dns)
{
  struct connectdata *conn = data->conn;
  const char *hostname = NULL;
  uint16_t port = 0;
  bool abstract_unix_socket = FALSE, for_proxy = FALSE;

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
  if(!hostname && conn->bits.proxy) {
    for_proxy = TRUE;
    hostname = conn->bits.socksproxy ?
      conn->socks_proxy.host.name : conn->http_proxy.host.name;
    port = conn->bits.socksproxy ?
      conn->socks_proxy.port : conn->http_proxy.port;
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
  return cf_dns_create(pcf, data, dns_queries,
                       hostname, port, transport,
                       abstract_unix_socket, for_proxy,
                       complete_resolve, dns);
}

/* Adds a "resolv" filter at the top of the connection's filter chain.
 * For FIRSTSOCKET, the `dns` parameter may be NULL. The filter will
 * figure out hostname and port to connect to and start the DNS resolve
 * on the first connect attempt.
 * For SECONDARYSOCKET, the `dns` parameter must be given.
 */
CURLcode Curl_cf_dns_add(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         uint8_t dns_queries,
                         uint8_t transport,
                         struct Curl_dns_entry *dns)
{
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  DEBUGASSERT(data);
  if(sockindex == FIRSTSOCKET)
    result = cf_dns_conn_create(&cf, data, dns_queries, transport, FALSE, dns);
  else if(dns) {
    result = cf_dns_create(&cf, data, dns_queries,
                           dns->hostname, dns->port, transport,
                           FALSE, FALSE, FALSE, dns);
  }
  else {
    DEBUGASSERT(0);
    result = CURLE_FAILED_INIT;
  }
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

/* Insert a new "resolv" filter directly after `cf`. It will
 * start a DNS resolve for the given hostnmae and port on the
 * first connect attempt.
 * See socks.c on how this is used to make a non-blocking DNS
 * resolve during connect.
 */
CURLcode Curl_cf_dns_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data,
                                  uint8_t dns_queries,
                                  const char *hostname,
                                  uint16_t port,
                                  uint8_t transport,
                                  bool complete_resolve)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_dns_create(&cf, data, dns_queries,
                         hostname, port, transport,
                         FALSE, FALSE, complete_resolve, NULL);
  if(result)
    return result;

  Curl_conn_cf_insert_after(cf_at, cf);
  return CURLE_OK;
}

/* Return the resolv result from the first "resolv" filter, starting
 * the given filter `cf` downwards.
 */
static CURLcode cf_dns_result(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_dns) {
      struct cf_dns_ctx *ctx = cf->ctx;
      if(ctx->dns || ctx->resolv_result)
        return ctx->resolv_result;
      return CURLE_AGAIN;
    }
  }
  return CURLE_FAILED_INIT;
}

/* Return the result of the DNS resolution. Searches for a "resolv"
 * filter from the top of the filter chain down. Returns
 * - CURLE_AGAIN when not done yet
 * - CURLE_OK when DNS was successfully resolved
 * - CURLR_FAILED_INIT when no resolv filter was found
 * - error returned by the DNS resolv
 */
CURLcode Curl_conn_dns_result(struct connectdata *conn, int sockindex)
{
  return cf_dns_result(conn->cfilter[sockindex]);
}

static const struct Curl_addrinfo *cf_dns_get_nth_ai(
  struct Curl_cfilter *cf,
  const struct Curl_addrinfo *ai,
  int ai_family, unsigned int index)
{
  struct cf_dns_ctx *ctx = cf->ctx;
  unsigned int i = 0;

  if((ai_family == AF_INET) && !(ctx->dns_queries & CURL_DNSQ_A))
    return NULL;
#ifdef USE_IPV6
  if((ai_family == AF_INET6) && !(ctx->dns_queries & CURL_DNSQ_AAAA))
    return NULL;
#endif
  for(i = 0; ai; ai = ai->ai_next) {
    if(ai->ai_family == ai_family) {
      if(i == index)
        return ai;
      ++i;
    }
  }
  return NULL;
}

/* Return the addrinfo at `index` for the given `family` from the
 * first "resolve" filter underneath `cf`. If the DNS resolving is
 * not done yet or if no address for the family exists, returns NULL.
 */
const struct Curl_addrinfo *Curl_cf_dns_get_ai(struct Curl_cfilter *cf,
                                               struct Curl_easy *data,
                                               int ai_family,
                                               unsigned int index)
{
  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_dns) {
      struct cf_dns_ctx *ctx = cf->ctx;
      if(ctx->resolv_result)
        return NULL;
      else if(ctx->dns)
        return cf_dns_get_nth_ai(cf, ctx->dns->addr, ai_family, index);
      else
        return Curl_resolv_get_ai(data, ctx->resolv_id, ai_family, index);
    }
  }
  return NULL;
}

/* Return the addrinfo at `index` for the given `family` from the
 * first "resolve" filter at the connection. If the DNS resolving is
 * not done yet or if no address for the family exists, returns NULL.
 */
const struct Curl_addrinfo *Curl_conn_dns_get_ai(struct Curl_easy *data,
                                                 int sockindex, int ai_family,
                                                 unsigned int index)
{
  struct connectdata *conn = data->conn;
  return Curl_cf_dns_get_ai(conn->cfilter[sockindex], data, ai_family, index);
}

#ifdef USE_HTTPSRR
/* Return the HTTPS-RR info from the first "resolve" filter at the
 * connection. If the DNS resolving is not done yet or if there
 * is no HTTPS-RR info, returns NULL.
 */
const struct Curl_https_rrinfo *Curl_conn_dns_get_https(struct Curl_easy *data,
                                                        int sockindex)
{
  struct Curl_cfilter *cf = data->conn->cfilter[sockindex];
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_dns) {
      struct cf_dns_ctx *ctx = cf->ctx;
      if(ctx->dns)
        return ctx->dns->hinfo;
      else
        return Curl_resolv_get_https(data, ctx->resolv_id);
    }
  }
  return NULL;
}

bool Curl_conn_dns_resolved_https(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf = data->conn->cfilter[sockindex];
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_dns) {
      struct cf_dns_ctx *ctx = cf->ctx;
      if(ctx->dns)
        return TRUE;
      else
        return Curl_resolv_knows_https(data, ctx->resolv_id);
    }
  }
  return FALSE;
}

#endif /* USE_HTTPSRR */
