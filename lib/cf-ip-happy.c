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
#include "connect.h"
#include "cfilters.h"
#include "cf-ip-happy.h"
#include "curl_trc.h"
#include "multiif.h"
#include "progress.h"
#include "select.h"
#include "vquic/vquic.h" /* for quic cfilters */

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


struct transport_provider {
  int transport;
  cf_ip_connect_create *cf_create;
};

static
#ifndef UNITTESTS
const
#endif
struct transport_provider transport_providers[] = {
  { TRNSPRT_TCP, Curl_cf_tcp_create },
#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)
  { TRNSPRT_QUIC, Curl_cf_quic_create },
#endif
#ifndef CURL_DISABLE_TFTP
  { TRNSPRT_UDP, Curl_cf_udp_create },
#endif
#ifdef USE_UNIX_SOCKETS
  { TRNSPRT_UNIX, Curl_cf_unix_create },
#endif
};

static cf_ip_connect_create *get_cf_create(int transport)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(transport_providers); ++i) {
    if(transport == transport_providers[i].transport)
      return transport_providers[i].cf_create;
  }
  return NULL;
}

#ifdef UNITTESTS
/* used by unit2600.c */
void Curl_debug_set_transport_provider(int transport,
                                       cf_ip_connect_create *cf_create)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(transport_providers); ++i) {
    if(transport == transport_providers[i].transport) {
      transport_providers[i].cf_create = cf_create;
      return;
    }
  }
}
#endif /* UNITTESTS */


struct cf_ai_iter {
  const struct Curl_addrinfo *head;
  const struct Curl_addrinfo *last;
  int ai_family;
  int n;
};

static void cf_ai_iter_init(struct cf_ai_iter *iter,
                            const struct Curl_addrinfo *list,
                            int ai_family)
{
  iter->head = list;
  iter->ai_family = ai_family;
  iter->last = NULL;
  iter->n = -1;
}

static const struct Curl_addrinfo *cf_ai_iter_next(struct cf_ai_iter *iter)
{
  const struct Curl_addrinfo *addr;
  if(iter->n < 0) {
    iter->n++;
    for(addr = iter->head; addr; addr = addr->ai_next) {
      if(addr->ai_family == iter->ai_family)
        break;
    }
    iter->last = addr;
  }
  else if(iter->last) {
    iter->n++;
    for(addr = iter->last->ai_next; addr; addr = addr->ai_next) {
      if(addr->ai_family == iter->ai_family)
        break;
    }
    iter->last = addr;
  }
  return iter->last;
}

#ifdef USE_IPV6
static bool cf_ai_iter_done(struct cf_ai_iter *iter)
{
  return (iter->n >= 0) && !iter->last;
}
#endif

struct cf_ip_attempt {
  struct cf_ip_attempt *next;
  const struct Curl_addrinfo *addr;  /* List of addresses to try, not owned */
  struct Curl_cfilter *cf;           /* current sub-cfilter connecting */
  cf_ip_connect_create *cf_create;
  struct curltime started;           /* start of current attempt */
  CURLcode result;
  int ai_family;
  int transport;
  int error;
  BIT(connected);                    /* cf has connected */
  BIT(shutdown);                     /* cf has shutdown */
  BIT(inconclusive);                 /* connect was not a hard failure, we
                                      * might talk to a restarting server */
};

static void cf_ip_attempt_free(struct cf_ip_attempt *a,
                               struct Curl_easy *data)
{
  if(a) {
    if(a->cf)
      Curl_conn_cf_discard_chain(&a->cf, data);
    free(a);
  }
}

static CURLcode cf_ip_attempt_new(struct cf_ip_attempt **pa,
                                  struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const struct Curl_addrinfo *addr,
                                  int ai_family,
                                  int transport,
                                  cf_ip_connect_create *cf_create)
{
  struct Curl_cfilter *wcf;
  struct cf_ip_attempt *a;
  CURLcode result = CURLE_OK;

  *pa = NULL;
  a = calloc(1, sizeof(*a));
  if(!a)
    return CURLE_OUT_OF_MEMORY;

  a->addr = addr;
  a->ai_family = ai_family;
  a->transport = transport;
  a->result = CURLE_OK;
  a->cf_create = cf_create;
  *pa = a;

  result = a->cf_create(&a->cf, data, cf->conn, a->addr, transport);
  if(result)
    goto out;

  /* the new filter might have sub-filters */
  for(wcf = a->cf; wcf; wcf = wcf->next) {
    wcf->conn = cf->conn;
    wcf->sockindex = cf->sockindex;
  }

out:
  if(result) {
    cf_ip_attempt_free(a, data);
    *pa = NULL;
  }
  return result;
}

static CURLcode cf_ip_attempt_connect(struct cf_ip_attempt *a,
                                      struct Curl_easy *data,
                                      bool *connected)
{
  *connected = a->connected;
  if(!a->result &&  !*connected) {
    /* evaluate again */
    a->result = Curl_conn_cf_connect(a->cf, data, connected);

    if(!a->result) {
      if(*connected) {
        a->connected = TRUE;
      }
    }
    else if(a->result == CURLE_WEIRD_SERVER_REPLY)
      a->inconclusive = TRUE;
  }
  return a->result;
}

struct cf_ip_ballers {
  struct cf_ip_attempt *running;
  struct cf_ip_attempt *winner;
  struct cf_ai_iter addr_iter;
#ifdef USE_IPV6
  struct cf_ai_iter ipv6_iter;
#endif
  cf_ip_connect_create *cf_create;   /* for creating cf */
  struct curltime started;
  struct curltime last_attempt_started;
  timediff_t attempt_delay_ms;
  int last_attempt_ai_family;
  int transport;
};

static CURLcode cf_ip_attempt_restart(struct cf_ip_attempt *a,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct Curl_cfilter *cf_prev = a->cf;
  struct Curl_cfilter *wcf;
  CURLcode result;

  /* When restarting, we tear down and existing filter *after* we
   * started up the new one. This gives us a new socket number and
   * probably a new local port. Which may prevent confusion. */
  a->result = CURLE_OK;
  a->connected = FALSE;
  a->inconclusive = FALSE;
  a->cf = NULL;

  result = a->cf_create(&a->cf, data, cf->conn, a->addr, a->transport);
  if(!result) {
    bool dummy;
    /* the new filter might have sub-filters */
    for(wcf = a->cf; wcf; wcf = wcf->next) {
      wcf->conn = cf->conn;
      wcf->sockindex = cf->sockindex;
    }
    a->result = cf_ip_attempt_connect(a, data, &dummy);
  }
  if(cf_prev)
    Curl_conn_cf_discard_chain(&cf_prev, data);
  return result;
}

static void cf_ip_ballers_clear(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct cf_ip_ballers *bs)
{
  (void)cf;
  while(bs->running) {
    struct cf_ip_attempt *a = bs->running;
    bs->running = a->next;
    cf_ip_attempt_free(a, data);
  }
  cf_ip_attempt_free(bs->winner, data);
  bs->winner = NULL;
}

static CURLcode cf_ip_ballers_init(struct cf_ip_ballers *bs, int ip_version,
                                   const struct Curl_addrinfo *addr_list,
                                   cf_ip_connect_create *cf_create,
                                   int transport,
                                   timediff_t attempt_delay_ms)
{
  memset(bs, 0, sizeof(*bs));
  bs->cf_create = cf_create;
  bs->transport = transport;
  bs->attempt_delay_ms = attempt_delay_ms;
  bs->last_attempt_ai_family = AF_INET; /* so AF_INET6 is next */

  if(transport == TRNSPRT_UNIX) {
#ifdef USE_UNIX_SOCKETS
    cf_ai_iter_init(&bs->addr_iter, addr_list, AF_UNIX);
#else
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }
  else { /* TCP/UDP/QUIC */
#ifdef USE_IPV6
    if(ip_version == CURL_IPRESOLVE_V6)
      cf_ai_iter_init(&bs->addr_iter, NULL, AF_INET);
    else
      cf_ai_iter_init(&bs->addr_iter, addr_list, AF_INET);

    if(ip_version == CURL_IPRESOLVE_V4)
      cf_ai_iter_init(&bs->ipv6_iter, NULL, AF_INET6);
    else
      cf_ai_iter_init(&bs->ipv6_iter, addr_list, AF_INET6);
#else
    (void)ip_version;
    cf_ai_iter_init(&bs->addr_iter, addr_list, AF_INET);
#endif
  }
  return CURLE_OK;
}

static CURLcode cf_ip_ballers_run(struct cf_ip_ballers *bs,
                                  struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *connected)
{
  CURLcode result = CURLE_OK;
  struct cf_ip_attempt *a = NULL, **panchor;
  bool do_more, more_possible;
  struct curltime now;
  timediff_t next_expire_ms;
  int i, inconclusive, ongoing;

  if(bs->winner)
    return CURLE_OK;

evaluate:
  now = curlx_now();
  ongoing = inconclusive = 0;
  more_possible = TRUE;

  /* check if a running baller connects now */
  i = -1;
  for(panchor = &bs->running; *panchor; panchor = &((*panchor)->next)) {
    ++i;
    a = *panchor;
    a->result = cf_ip_attempt_connect(a, data, connected);
    if(!a->result) {
      if(*connected) {
        /* connected, declare the winner, remove from running,
         * clear remaining running list. */
        CURL_TRC_CF(data, cf, "connect attempt #%d successful", i);
        bs->winner = a;
        *panchor = a->next;
        a->next = NULL;
        while(bs->running) {
          a = bs->running;
          bs->running = a->next;
          cf_ip_attempt_free(a, data);
        }
        return CURLE_OK;
      }
      /* still running */
      ++ongoing;
    }
    else if(a->inconclusive) /* failed, but inconclusive */
      ++inconclusive;
  }
  if(bs->running)
    CURL_TRC_CF(data, cf, "checked connect attempts: "
                "%d ongoing, %d inconclusive", ongoing, inconclusive);

  /* no attempt connected yet, start another one? */
  if(!ongoing) {
    if(!bs->started.tv_sec && !bs->started.tv_usec)
      bs->started = now;
    do_more = TRUE;
  }
  else {
    do_more = (curlx_timediff(now, bs->last_attempt_started) >=
               bs->attempt_delay_ms);
    if(do_more)
      CURL_TRC_CF(data, cf, "happy eyeballs timeout expired, "
                  "start next attempt");
  }

  if(do_more) {
    /* start the next attempt if there is another ip address to try.
     * Alternate between address families when possible. */
    const struct Curl_addrinfo *addr = NULL;
    int ai_family = 0;
#ifdef USE_IPV6
    if((bs->last_attempt_ai_family == AF_INET) ||
        cf_ai_iter_done(&bs->addr_iter)) {
       addr = cf_ai_iter_next(&bs->ipv6_iter);
       ai_family = bs->ipv6_iter.ai_family;
    }
#endif
    if(!addr) {
      addr = cf_ai_iter_next(&bs->addr_iter);
      ai_family = bs->addr_iter.ai_family;
    }

    if(addr) {  /* try another address */
      result = cf_ip_attempt_new(&a, cf, data, addr, ai_family,
                                bs->transport, bs->cf_create);
      CURL_TRC_CF(data, cf, "starting %s attempt for ipv%s -> %d",
                  bs->running ? "next" : "first",
                  (ai_family == AF_INET) ? "4" : "6", result);
      if(result)
        goto out;
      DEBUGASSERT(a);

      /* append to running list */
      panchor = &bs->running;
      while(*panchor)
        panchor = &((*panchor)->next);
      *panchor = a;
      bs->last_attempt_started = now;
      bs->last_attempt_ai_family = ai_family;
      /* and run everything again */
      goto evaluate;
    }
    else if(inconclusive) {
      /* tried all addresses, no success but some where inconclusive.
       * Let's restart the inconclusive ones. */
      if(curlx_timediff(now, bs->last_attempt_started) >=
         bs->attempt_delay_ms) {
        CURL_TRC_CF(data, cf, "tried all addresses with inconclusive results"
                    ", restarting one");
        i = -1;
        for(a = bs->running; a; a = a->next) {
          ++i;
          if(!a->inconclusive)
            continue;
          result = cf_ip_attempt_restart(a, cf, data);
          CURL_TRC_CF(data, cf, "restarted baller %d -> %d", i, result);
          if(result) /* serious failure */
            goto out;
          bs->last_attempt_started = now;
          goto evaluate;
        }
        DEBUGASSERT(0); /* should not come here */
      }
      /* attempt timeout for restart has not expired yet */
      goto out;
    }
    else if(ongoing) {
      /* no more addresses, no inconclusive attempts */
      more_possible = FALSE;
    }
    else {
      CURL_TRC_CF(data, cf, "no more attempts to try");
      result = CURLE_COULDNT_CONNECT;
      i = 0;
      for(a = bs->running; a; a = a->next) {
        CURL_TRC_CF(data, cf, "baller %d: result=%d", i, a->result);
        if(a->result)
          result = a->result;
      }
    }
  }

out:
  if(!result) {
    /* when do we need to be called again? */
    next_expire_ms = Curl_timeleft(data, &now, TRUE);
    if(more_possible) {
      timediff_t expire_ms, elapsed_ms;
      elapsed_ms = curlx_timediff(now, bs->last_attempt_started);
      expire_ms = CURLMAX(bs->attempt_delay_ms - elapsed_ms, 0);
      next_expire_ms = CURLMIN(next_expire_ms, expire_ms);
    }

    if(next_expire_ms <= 0) {
      failf(data, "Connection timeout after %" FMT_OFF_T " ms",
            curlx_timediff(now, data->progress.t_startsingle));
      return CURLE_OPERATION_TIMEDOUT;
    }
    Curl_expire(data, next_expire_ms, EXPIRE_HAPPY_EYEBALLS);
  }
  return result;
}

static CURLcode cf_ip_ballers_shutdown(struct cf_ip_ballers *bs,
                                       struct Curl_easy *data,
                                       bool *done)
{
  struct cf_ip_attempt *a;

  /* shutdown all ballers that have not done so already. If one fails,
   * continue shutting down others until all are shutdown. */
  *done = TRUE;
  for(a = bs->running; a; a = a->next) {
    bool bdone = FALSE;
    if(a->shutdown)
      continue;
    a->result = a->cf->cft->do_shutdown(a->cf, data, &bdone);
    if(a->result || bdone)
      a->shutdown = TRUE; /* treat a failed shutdown as done */
    else
      *done = FALSE;
  }
  return CURLE_OK;
}

static CURLcode cf_ip_ballers_pollset(struct cf_ip_ballers *bs,
                                      struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  struct cf_ip_attempt *a;
  CURLcode result = CURLE_OK;
  for(a = bs->running; a && !result; a = a->next) {
    if(a->result)
      continue;
    result = Curl_conn_cf_adjust_pollset(a->cf, data, ps);
  }
  return result;
}

static bool cf_ip_ballers_pending(struct cf_ip_ballers *bs,
                                  const struct Curl_easy *data)
{
  struct cf_ip_attempt *a;

  for(a = bs->running; a; a = a->next) {
    if(a->result)
      continue;
    if(a->cf->cft->has_data_pending(a->cf, data))
      return TRUE;
  }
  return FALSE;
}

static struct curltime cf_ip_ballers_max_time(struct cf_ip_ballers *bs,
                                              struct Curl_easy *data,
                                              int query)
{
  struct curltime t, tmax;
  struct cf_ip_attempt *a;

  memset(&tmax, 0, sizeof(tmax));
  for(a = bs->running; a; a = a->next) {
    memset(&t, 0, sizeof(t));
    if(!a->cf->cft->query(a->cf, data, query, NULL, &t)) {
      if((t.tv_sec || t.tv_usec) && curlx_timediff_us(t, tmax) > 0)
        tmax = t;
    }
  }
  return tmax;
}

static int cf_ip_ballers_min_reply_ms(struct cf_ip_ballers *bs,
                                      struct Curl_easy *data)
{
  int reply_ms = -1, breply_ms;
  struct cf_ip_attempt *a;

  for(a = bs->running; a; a = a->next) {
    if(!a->cf->cft->query(a->cf, data, CF_QUERY_CONNECT_REPLY_MS,
                          &breply_ms, NULL)) {
      if(breply_ms >= 0 && (reply_ms < 0 || breply_ms < reply_ms))
        reply_ms = breply_ms;
    }
  }
  return reply_ms;
}


typedef enum {
  SCFST_INIT,
  SCFST_WAITING,
  SCFST_DONE
} cf_connect_state;

struct cf_ip_happy_ctx {
  int transport;
  cf_ip_connect_create *cf_create;
  cf_connect_state state;
  struct cf_ip_ballers ballers;
  struct curltime started;
};


static CURLcode is_connected(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             bool *connected)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;
  struct connectdata *conn = cf->conn;
  CURLcode result;

  result = cf_ip_ballers_run(&ctx->ballers, cf, data, connected);

  if(!result)
    return CURLE_OK;

  {
    const char *hostname, *proxy_name = NULL;
    int port;
#ifndef CURL_DISABLE_PROXY
    if(conn->bits.socksproxy)
      proxy_name = conn->socks_proxy.host.name;
    else if(conn->bits.httpproxy)
      proxy_name = conn->http_proxy.host.name;
#endif
    hostname = conn->bits.conn_to_host ?
               conn->conn_to_host.name : conn->host.name;

    if(cf->sockindex == SECONDARYSOCKET)
      port = conn->secondary_port;
    else if(cf->conn->bits.conn_to_port)
      port = conn->conn_to_port;
    else
      port = conn->remote_port;

    failf(data, "Failed to connect to %s port %u %s%s%safter "
          "%" FMT_TIMEDIFF_T " ms: %s",
          hostname, port,
          proxy_name ? "via " : "",
          proxy_name ? proxy_name : "",
          proxy_name ? " " : "",
          curlx_timediff(curlx_now(), data->progress.t_startsingle),
          curl_easy_strerror(result));
  }

#ifdef SOCKETIMEDOUT
  if(SOCKETIMEDOUT == data->state.os_errno)
    result = CURLE_OPERATION_TIMEDOUT;
#endif

  return result;
}

/*
 * Connect to the given host with timeout, proxy or remote does not matter.
 * There might be more than one IP address to try out.
 */
static CURLcode start_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;
  struct Curl_dns_entry *dns = data->state.dns[cf->sockindex];

  if(!dns)
    return CURLE_FAILED_INIT;

  if(Curl_timeleft(data, NULL, TRUE) < 0) {
    /* a precaution, no need to continue if time already is up */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  CURL_TRC_CF(data, cf, "init ip ballers for transport %d", ctx->transport);
  ctx->started = curlx_now();
  return cf_ip_ballers_init(&ctx->ballers, cf->conn->ip_version,
                            dns->addr, ctx->cf_create, ctx->transport,
                            data->set.happy_eyeballs_timeout);
}

static void cf_ip_happy_ctx_clear(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;

  DEBUGASSERT(ctx);
  DEBUGASSERT(data);
  cf_ip_ballers_clear(cf, data, &ctx->ballers);
}

static CURLcode cf_ip_happy_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     bool *done)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf_ip_ballers_shutdown(&ctx->ballers, data, done);
  CURL_TRC_CF(data, cf, "shutdown -> %d, done=%d", result, *done);
  return result;
}

static CURLcode cf_ip_happy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!cf->connected) {
    result = cf_ip_ballers_pollset(&ctx->ballers, data, ps);
    CURL_TRC_CF(data, cf, "adjust_pollset -> %d, %d socks", result, ps->n);
  }
  return result;
}

static CURLcode cf_ip_happy_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *done)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  DEBUGASSERT(ctx);
  *done = FALSE;

  switch(ctx->state) {
    case SCFST_INIT:
      DEBUGASSERT(CURL_SOCKET_BAD == Curl_conn_cf_get_socket(cf, data));
      DEBUGASSERT(!cf->connected);
      result = start_connect(cf, data);
      if(result)
        return result;
      ctx->state = SCFST_WAITING;
      FALLTHROUGH();
    case SCFST_WAITING:
      result = is_connected(cf, data, done);
      if(!result && *done) {
        DEBUGASSERT(ctx->ballers.winner);
        DEBUGASSERT(ctx->ballers.winner->cf);
        DEBUGASSERT(ctx->ballers.winner->cf->connected);
        /* we have a winner. Install and activate it.
         * close/free all others. */
        ctx->state = SCFST_DONE;
        cf->connected = TRUE;
        cf->next = ctx->ballers.winner->cf;
        ctx->ballers.winner->cf = NULL;
        cf_ip_happy_ctx_clear(cf, data);
        Curl_expire_done(data, EXPIRE_HAPPY_EYEBALLS);

        if(cf->conn->handler->protocol & PROTO_FAMILY_SSH)
          Curl_pgrsTime(data, TIMER_APPCONNECT); /* we are connected already */
#ifndef CURL_DISABLE_VERBOSE_STRINGS
        if(Curl_trc_cf_is_verbose(cf, data)) {
          struct ip_quadruple ipquad;
          bool is_ipv6;
          if(!Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad)) {
            const char *host;
            int port;
            Curl_conn_get_current_host(data, cf->sockindex, &host, &port);
            CURL_TRC_CF(data, cf, "Connected to %s (%s) port %u",
                        host, ipquad.remote_ip, ipquad.remote_port);
          }
        }
#endif
        data->info.numconnects++; /* to track the # of connections made */
      }
      break;
    case SCFST_DONE:
      *done = TRUE;
      break;
  }
  return result;
}

static void cf_ip_happy_close(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf_ip_happy_ctx_clear(cf, data);
  cf->connected = FALSE;
  ctx->state = SCFST_INIT;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static bool cf_ip_happy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;

  if(!cf->connected) {
    return cf_ip_ballers_pending(&ctx->ballers, data);
  }
  return cf->next->cft->has_data_pending(cf->next, data);
}

static CURLcode cf_ip_happy_query(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int query, int *pres1, void *pres2)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;

  if(!cf->connected) {
    switch(query) {
    case CF_QUERY_CONNECT_REPLY_MS: {
      *pres1 = cf_ip_ballers_min_reply_ms(&ctx->ballers, data);
      CURL_TRC_CF(data, cf, "query connect reply: %dms", *pres1);
      return CURLE_OK;
    }
    case CF_QUERY_TIMER_CONNECT: {
      struct curltime *when = pres2;
      *when = cf_ip_ballers_max_time(&ctx->ballers, data,
                                     CF_QUERY_TIMER_CONNECT);
      return CURLE_OK;
    }
    case CF_QUERY_TIMER_APPCONNECT: {
      struct curltime *when = pres2;
      *when = cf_ip_ballers_max_time(&ctx->ballers, data,
                                     CF_QUERY_TIMER_APPCONNECT);
      return CURLE_OK;
    }
    default:
      break;
    }
  }

  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static void cf_ip_happy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_ip_happy_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  if(ctx) {
    cf_ip_happy_ctx_clear(cf, data);
  }
  /* release any resources held in state */
  Curl_safefree(ctx);
}

struct Curl_cftype Curl_cft_ip_happy = {
  "HAPPY-EYEBALLS",
  0,
  CURL_LOG_LVL_NONE,
  cf_ip_happy_destroy,
  cf_ip_happy_connect,
  cf_ip_happy_close,
  cf_ip_happy_shutdown,
  cf_ip_happy_adjust_pollset,
  cf_ip_happy_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_ip_happy_query,
};

/**
 * Create an IP happy eyeball connection filter that uses the, once resolved,
 * address information to connect on ip families based on connection
 * configuration.
 * @param pcf        output, the created cfilter
 * @param data       easy handle used in creation
 * @param conn       connection the filter is created for
 * @param cf_create  method to create the sub-filters performing the
 *                   actual connects.
 */
static CURLcode cf_ip_happy_create(struct Curl_cfilter **pcf,
                                   struct Curl_easy *data,
                                   struct connectdata *conn,
                                   cf_ip_connect_create *cf_create,
                                   int transport)
{
  struct cf_ip_happy_ctx *ctx = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  *pcf = NULL;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->transport = transport;
  ctx->cf_create = cf_create;

  result = Curl_cf_create(pcf, &Curl_cft_ip_happy, ctx);

out:
  if(result) {
    Curl_safefree(*pcf);
    free(ctx);
  }
  return result;
}

CURLcode cf_ip_happy_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data,
                                  int transport)
{
  cf_ip_connect_create *cf_create;
  struct Curl_cfilter *cf;
  CURLcode result;

  /* Need to be first */
  DEBUGASSERT(cf_at);
  cf_create = get_cf_create(transport);
  if(!cf_create) {
    CURL_TRC_CF(data, cf_at, "unsupported transport type %d", transport);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }
  result = cf_ip_happy_create(&cf, data, cf_at->conn, cf_create, transport);
  if(result)
    return result;

  Curl_conn_cf_insert_after(cf_at, cf);
  return CURLE_OK;
}
