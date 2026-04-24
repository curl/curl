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

/***********************************************************************
 * Only for threaded name resolves builds
 **********************************************************************/
#ifdef USE_RESOLV_THREADED

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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

#ifdef HAVE_GETADDRINFO
#define RESOLVER_ENOMEM  EAI_MEMORY  /* = WSA_NOT_ENOUGH_MEMORY on Windows */
#else
#define RESOLVER_ENOMEM  SOCKENOMEM
#endif

#include "urldata.h"
#include "cfilters.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "hostip.h"
#include "httpsrr.h"
#include "url.h"
#include "multiif.h"
#include "curl_threads.h"
#include "progress.h"
#include "rand.h"
#include "select.h"
#include "thrdqueue.h"
#include "curlx/strparse.h"
#include "curlx/wait.h"

#ifdef USE_ARES
#include <ares.h>
#ifdef USE_HTTPSRR
#define USE_HTTPSRR_ARES  /* the combo */
#endif
#endif


/*
 * Curl_async_global_init()
 * Called from curl_global_init() to initialize global resolver environment.
 * Does nothing here.
 */
int Curl_async_global_init(void)
{
#if defined(USE_ARES) && defined(CARES_HAVE_ARES_LIBRARY_INIT)
  if(ares_library_init(ARES_LIB_INIT_ALL)) {
    return CURLE_FAILED_INIT;
  }
#endif
  return CURLE_OK;
}

/*
 * Curl_async_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 * Does nothing here.
 */
void Curl_async_global_cleanup(void)
{
#if defined(USE_ARES) && defined(CARES_HAVE_ARES_LIBRARY_INIT)
  ares_library_cleanup();
#endif
}

#ifdef CURLVERBOSE
#define CURL_ASYN_ITEM_DESC_LEN   64
#define async_item_description(x)   (x)->description
#else
#define async_item_description(x)   NULL
#endif

struct async_thrdd_item {
  struct Curl_addrinfo *res;
#ifdef CURLVERBOSE
  char description[CURL_ASYN_ITEM_DESC_LEN];
#endif
  int sock_error;
  uint32_t mid;
  uint32_t resolv_id;
  uint16_t port;
  uint8_t transport;
  uint8_t dns_queries;
#ifdef DEBUGBUILD
  uint32_t delay_ms;
  uint32_t delay_fail_ms;
#endif
  char hostname[1];
};

/* Give up reference to add_ctx */
static void async_thrdd_item_destroy(struct async_thrdd_item *item)
{
  if(item) {
    if(item->res)
      Curl_freeaddrinfo(item->res);
    curlx_free(item);
  }
}

/* Initialize context for threaded resolver */
static struct async_thrdd_item *async_thrdd_item_create(
  struct Curl_easy *data,
  uint32_t resolv_id, uint8_t dns_queries,
  const char *hostname, uint16_t port,
  uint8_t transport)
{
  size_t hostlen = strlen(hostname);
  struct async_thrdd_item *item;

  item = curlx_calloc(1, sizeof(*item) + hostlen);
  if(!item)
    return NULL;

  if(hostlen) /* NUL byte of name already in struct size */
    memcpy(item->hostname, hostname, hostlen);
  item->mid = data->mid;
  item->resolv_id = resolv_id;
  item->dns_queries = dns_queries;
  item->port = port;
  item->transport = transport;

#ifdef CURLVERBOSE
  curl_msnprintf(item->description, sizeof(item->description),
                 "[%" FMT_OFF_T "/%u] %s %s:%u",
                 data->id, item->resolv_id,
                 Curl_resolv_query_str(dns_queries),
                 item->hostname, item->port);
#endif

#ifdef DEBUGBUILD
  {
    const char *p = getenv("CURL_DBG_RESOLV_DELAY");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, UINT32_MAX)) {
        item->delay_ms = (uint32_t)l;
      }
    }
    p = getenv("CURL_DBG_RESOLV_FAIL_DELAY");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, UINT32_MAX)) {
        unsigned char c = 0;
        Curl_rand_bytes(data, FALSE, &c, 1);
        item->delay_fail_ms = (uint32_t)l + c;
      }
    }
  }
#endif

  return item;
}

#ifdef USE_HTTPSRR_ARES

static void async_thrdd_rr_done(void *user_data, ares_status_t status,
                                size_t timeouts,
                                const ares_dns_record_t *dnsrec)
{
  struct Curl_resolv_async *async = user_data;
  struct async_thrdd_ctx *thrdd = async ? &async->thrdd : NULL;

  (void)timeouts;
  if(!thrdd)
    return;

  async->dns_responses |= CURL_DNSQ_HTTPS;
  async->queries_ongoing--;
  async->done = !async->queries_ongoing;
  if((ARES_SUCCESS == status) && dnsrec)
    async->result = Curl_httpsrr_from_ares(dnsrec, &thrdd->rr.hinfo);
}

static CURLcode async_rr_start(struct Curl_easy *data,
                               struct Curl_resolv_async *async)
{
  struct async_thrdd_ctx *thrdd = &async->thrdd;
  int status;
  char *rrname = NULL;

  DEBUGASSERT(!thrdd->rr.channel);
  if(async->port != 443) {
    rrname = curl_maprintf("_%d_.https.%s", async->port, async->hostname);
    if(!rrname)
      return CURLE_OUT_OF_MEMORY;
  }
  status = ares_init_options(&thrdd->rr.channel, NULL, 0);
  if(status != ARES_SUCCESS) {
    thrdd->rr.channel = NULL;
    curlx_free(rrname);
    return CURLE_FAILED_INIT;
  }
#ifdef DEBUGBUILD
  if(getenv("CURL_DNS_SERVER")) {
    const char *servers = getenv("CURL_DNS_SERVER");
    status = ares_set_servers_ports_csv(thrdd->rr.channel, servers);
    if(status) {
      curlx_free(rrname);
      return CURLE_FAILED_INIT;
    }
  }
#endif

  memset(&thrdd->rr.hinfo, 0, sizeof(thrdd->rr.hinfo));
  thrdd->rr.hinfo.rrname = rrname;
  async->queries_ongoing++;
  ares_query_dnsrec(thrdd->rr.channel,
                    rrname ? rrname : async->hostname, ARES_CLASS_IN,
                    ARES_REC_TYPE_HTTPS,
                    async_thrdd_rr_done, async, NULL);
  CURL_TRC_DNS(data, "[HTTPS-RR] initiated request for %s",
               rrname ? rrname : async->hostname);
  return CURLE_OK;
}
#endif

void Curl_async_thrdd_shutdown(struct Curl_easy *data,
                               struct Curl_resolv_async *async)
{
  Curl_async_thrdd_destroy(data, async);
}

struct async_thrdd_match_ctx {
  uint32_t mid;
  uint32_t resolv_id;
};

static bool async_thrdd_match_item(void *qitem, void *match_data)
{
  const struct async_thrdd_match_ctx *ctx = match_data;
  struct async_thrdd_item *item = qitem;
  return (item->mid == ctx->mid) && (item->resolv_id == ctx->resolv_id);
}

void Curl_async_thrdd_destroy(struct Curl_easy *data,
                              struct Curl_resolv_async *async)
{
  (void)data;
  if(async->queries_ongoing && !async->done &&
     data->multi && data->multi->resolv_thrdq) {
    /* Remove any resolve items still queued */
    struct async_thrdd_match_ctx mctx;
    mctx.mid = data->mid;
    mctx.resolv_id = async->id;
    Curl_thrdq_clear(data->multi->resolv_thrdq,
                     async_thrdd_match_item, &mctx);
  }
#ifdef USE_HTTPSRR_ARES
  if(async->thrdd.rr.channel) {
    ares_destroy(async->thrdd.rr.channel);
    async->thrdd.rr.channel = NULL;
  }
  Curl_httpsrr_cleanup(&async->thrdd.rr.hinfo);
#endif
  async_thrdd_item_destroy(async->thrdd.res_A);
  async->thrdd.res_A = NULL;
  async_thrdd_item_destroy(async->thrdd.res_AAAA);
  async->thrdd.res_AAAA = NULL;
}

/*
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 */
CURLcode Curl_async_await(struct Curl_easy *data, uint32_t resolv_id,
                          struct Curl_dns_entry **pdns)
{
  struct Curl_resolv_async *async = Curl_async_get(data, resolv_id);
  struct async_thrdd_ctx *thrdd = async ? &async->thrdd : NULL;
  timediff_t milli, ms;

  if(!thrdd)
    return CURLE_FAILED_INIT;

  while(async->queries_ongoing && !async->done) {
    Curl_async_thrdd_multi_process(data->multi);
    if(async->done)
      break;

    ms = curlx_ptimediff_ms(Curl_pgrs_now(data), &async->start);
    if(ms < 3)
      milli = 0;
    else if(ms <= 50)
      milli = ms / 3;
    else if(ms <= 250)
      milli = 50;
    else
      milli = 200;
    CURL_TRC_DNS(data, "await, waiting %" FMT_TIMEDIFF_T "ms", milli);
    curlx_wait_ms(milli);
  }
  return Curl_async_take_result(data, async, pdns);
}

#ifdef HAVE_GETADDRINFO

/* Process the item, using Curl_getaddrinfo_ex() */
static void async_thrdd_item_process(void *arg)
{
  struct async_thrdd_item *item = arg;
  struct addrinfo hints;
  char service[12];
  int pf = PF_INET;
  int rc;

#ifdef DEBUGBUILD
  if(item->delay_ms) {
    curlx_wait_ms(item->delay_ms);
  }
  if(item->delay_fail_ms) {
    curlx_wait_ms(item->delay_fail_ms);
    return;
  }
#endif

  memset(&hints, 0, sizeof(hints));
#ifdef CURLRES_IPV6
  if(item->dns_queries & CURL_DNSQ_AAAA) {
    pf = (item->dns_queries & CURL_DNSQ_A) ? PF_UNSPEC : PF_INET6;
  }
#endif
  hints.ai_family = pf;
  hints.ai_socktype = Curl_socktype_for_transport(item->transport);
  hints.ai_protocol = Curl_protocol_for_transport(item->transport);
#ifdef __APPLE__
  /* If we leave `ai_flags == 0` then macOS is looking for IPV4MAPPED
   * when doing AAAA queries. We do not want this "help". */
  hints.ai_flags = AI_ADDRCONFIG;
#endif

  curl_msnprintf(service, sizeof(service), "%u", item->port);
#ifdef AI_NUMERICSERV
  hints.ai_flags |= AI_NUMERICSERV;
#endif

  rc = Curl_getaddrinfo_ex(item->hostname, service, &hints, &item->res);
  if(rc) {
    item->sock_error = SOCKERRNO ? SOCKERRNO : rc;
    if(item->sock_error == 0)
      item->sock_error = RESOLVER_ENOMEM;
  }
  else {
    Curl_addrinfo_set_port(item->res, item->port);
  }
}

#else /* HAVE_GETADDRINFO */

/* Process the item, using Curl_ipv4_resolve_r() */
static void async_thrdd_item_process(void *arg)
{
  struct async_thrdd_item *item = arg;

#ifdef DEBUGBUILD
  if(item->delay_ms) {
    curlx_wait_ms(item->delay_ms);
  }
  if(item->delay_fail_ms) {
    curlx_wait_ms(item->delay_fail_ms);
    return;
  }
#endif
  item->res = Curl_ipv4_resolve_r(item->hostname, item->port);
  if(!item->res) {
    item->sock_error = SOCKERRNO;
    if(item->sock_error == 0)
      item->sock_error = RESOLVER_ENOMEM;
  }
}

#endif /* HAVE_GETADDRINFO */

#ifdef ENABLE_WAKEUP
static void async_thrdd_event(const struct curl_thrdq *tqueue,
                              Curl_thrdq_event ev,
                              void *user_data)
{
  struct Curl_multi *multi = user_data;
  (void)tqueue;
  switch(ev) {
  case CURL_THRDQ_EV_ITEM_DONE:
    (void)curl_multi_wakeup(multi);
    break;
  default:
    break;
  }
}
#else
#define async_thrdd_event   NULL
#endif

static void async_thrdd_item_free(void *item)
{
  async_thrdd_item_destroy(item);
}

/* Create a thread queue for processing resolv items */
CURLcode Curl_async_thrdd_multi_init(struct Curl_multi *multi,
                                     uint32_t min_threads,
                                     uint32_t max_threads,
                                     uint32_t idle_time_ms)
{
  CURLcode result;
  DEBUGASSERT(!multi->resolv_thrdq);
  result = Curl_thrdq_create(&multi->resolv_thrdq, "DNS", 0,
                             min_threads, max_threads, idle_time_ms,
                             async_thrdd_item_free,
                             async_thrdd_item_process,
                             async_thrdd_event,
                             multi);
#ifdef DEBUGBUILD
  if(!result) {
    const char *p = getenv("CURL_DBG_RESOLV_MAX_THREADS");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, UINT32_MAX)) {
        result = Curl_async_thrdd_multi_set_props(
          multi, min_threads, (uint32_t)l, idle_time_ms);
      }
    }
  }
#endif
  return result;
}

/* Tear down the thread queue, joining active threads or detaching them */
void Curl_async_thrdd_multi_destroy(struct Curl_multi *multi, bool join)
{
  if(multi->resolv_thrdq) {
#ifdef CURLVERBOSE
    CURL_TRC_DNS(multi->admin, "destroy thread queue+pool, join=%d", join);
    Curl_thrdq_trace(multi->resolv_thrdq, multi->admin);
#endif
    Curl_thrdq_destroy(multi->resolv_thrdq, join);
    multi->resolv_thrdq = NULL;
  }
}

#ifdef CURLVERBOSE
static void async_thrdd_report_item(struct Curl_easy *data,
                                    struct async_thrdd_item *item)
{
  char buf[MAX_IPADR_LEN];
  struct dynbuf tmp;
  const char *sep = "";
  const struct Curl_addrinfo *ai = item->res;
  int ai_family = (item->dns_queries & CURL_DNSQ_AAAA) ? AF_INET6 : AF_INET;
  CURLcode result;

  if(!CURL_TRC_DNS_is_verbose(data))
    return;

  curlx_dyn_init(&tmp, 1024);
  for(; ai; ai = ai->ai_next) {
    if(ai->ai_family == ai_family) {
      Curl_printable_address(ai, buf, sizeof(buf));
      result = curlx_dyn_addf(&tmp, "%s%s", sep, buf);
      if(result) {
        CURL_TRC_DNS(data, "too many IP, cannot show");
        goto out;
      }
      sep = ", ";
    }
  }

  CURL_TRC_DNS(data, "Host %s:%u resolved IPv%c: %s",
               item->hostname, item->port,
               (item->dns_queries & CURL_DNSQ_AAAA) ? '6' : '4',
               (curlx_dyn_len(&tmp) ? curlx_dyn_ptr(&tmp) : "(none)"));
out:
  curlx_dyn_free(&tmp);
}
#endif /* CURLVERBOSE */

/* Process the receiving end of the thread queue, dispatching
 * processed items to their transfer when it can still be found
 * and has an `async` state present. Otherwise, destroy the item. */
void Curl_async_thrdd_multi_process(struct Curl_multi *multi)
{
  struct Curl_easy *data;
  void *qitem;

  while(!Curl_thrdq_recv(multi->resolv_thrdq, &qitem)) {
    /* dispatch resolve result */
    struct async_thrdd_item *item = qitem;
    struct Curl_resolv_async *async = NULL;

    data = Curl_multi_get_easy(multi, item->mid);
    if(data)
      async = Curl_async_get(data, item->resolv_id);
    if(async) {
      struct async_thrdd_item **pdest = &async->thrdd.res_A;

      async->dns_responses |= item->dns_queries;
      --async->queries_ongoing;
      async->done = !async->queries_ongoing;

#ifdef CURLRES_IPV6
      if(item->dns_queries & CURL_DNSQ_AAAA)
        pdest = &async->thrdd.res_AAAA;
#endif
      if(!*pdest) {
        VERBOSE(async_thrdd_report_item(data, item));
        *pdest = item;
        item = NULL;
      }
      else
        DEBUGASSERT(0); /* should not receive duplicates here */
      Curl_multi_mark_dirty(data);
    }
    async_thrdd_item_free(item);
  }
#ifdef CURLVERBOSE
  Curl_thrdq_trace(multi->resolv_thrdq, multi->admin);
#endif
}

CURLcode Curl_async_thrdd_multi_set_props(struct Curl_multi *multi,
                                          uint32_t min_threads,
                                          uint32_t max_threads,
                                          uint32_t idle_time_ms)
{
  return Curl_thrdq_set_props(multi->resolv_thrdq, 0,
                              min_threads, max_threads, idle_time_ms);
}

static CURLcode async_thrdd_query(struct Curl_easy *data,
                                  struct Curl_resolv_async *async,
                                  uint8_t dns_queries)
{
  struct async_thrdd_item *item;
  CURLcode result;

  item = async_thrdd_item_create(data, async->id, dns_queries,
                                 async->hostname, async->port,
                                 async->transport);
  if(!item) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  CURL_TRC_DNS(data, "queueing query %s", item->description);
  result = Curl_thrdq_send(data->multi->resolv_thrdq, item,
                           async_item_description(item), async->timeout_ms);
  if(result)
    goto out;
  item = NULL;
  async->queries_ongoing++;

out:
  if(item)
    async_thrdd_item_free(item);
  return result;
}

CURLcode Curl_async_getaddrinfo(struct Curl_easy *data,
                                struct Curl_resolv_async *async)
{
  CURLcode result = CURLE_FAILED_INIT;
  void *resolver = NULL;

  if(async->queries_ongoing || async->done)
    return CURLE_FAILED_INIT;

#ifdef USE_HTTPSRR_ARES
  DEBUGASSERT(!async->thrdd.rr.channel);
  if((async->dns_queries & CURL_DNSQ_HTTPS) && !async->is_ipaddr) {
    result = async_rr_start(data, async);
    if(result)
      goto out;
    resolver = async->thrdd.rr.channel;
  }
#endif

  result = Curl_resolv_announce_start(data, resolver);
  if(result)
    return result;

#ifdef CURLRES_IPV6
  /* Do not start an AAAA query for an ipv4 address when
   * we will start an A query for it. */
  if((async->dns_queries & CURL_DNSQ_AAAA) &&
     !(async->is_ipv4addr && (async->dns_queries & CURL_DNSQ_A))) {
    result = async_thrdd_query(data, async, CURL_DNSQ_AAAA);
    if(result)
      goto out;
  }
#endif
  if(async->dns_queries & CURL_DNSQ_A) {
    result = async_thrdd_query(data, async, CURL_DNSQ_A);
    if(result)
      goto out;
  }

#ifdef CURLVERBOSE
  Curl_thrdq_trace(data->multi->resolv_thrdq, data);
#endif

out:
  if(result)
    CURL_TRC_DNS(data, "error queueing query %s:%d -> %d",
                 async->hostname, async->port, result);
  return result;
}

CURLcode Curl_async_pollset(struct Curl_easy *data,
                            struct Curl_resolv_async *async,
                            struct easy_pollset *ps)
{
  timediff_t timeout_ms;

  timeout_ms = Curl_async_timeleft_ms(data, async);
#ifdef USE_HTTPSRR_ARES
  if(async->thrdd.rr.channel) {
    CURLcode result = Curl_ares_pollset(data, async->thrdd.rr.channel, ps);
    if(result)
      return result;
    timeout_ms = Curl_ares_timeout_ms(data, async, async->thrdd.rr.channel);
  }
#else
  (void)ps;
#endif

  if(!async->done) {
#ifndef ENABLE_WAKEUP
    timediff_t stutter_ms, elapsed_ms;
    elapsed_ms = curlx_ptimediff_ms(Curl_pgrs_now(data), &async->start);
    if(elapsed_ms < 3)
      stutter_ms = 1;
    else if(elapsed_ms <= 50)
      stutter_ms = elapsed_ms / 3;
    else if(elapsed_ms <= 250)
      stutter_ms = 50;
    else
      stutter_ms = 200;
    timeout_ms = CURLMIN(stutter_ms, timeout_ms);
#endif
    Curl_expire(data, timeout_ms, EXPIRE_ASYNC_NAME);
  }
  return CURLE_OK;
}

/*
 * Curl_async_take_result() is called repeatedly to check if a previous
 * name resolve request has completed. It should also make sure to time-out if
 * the operation seems to take too long.
 */
CURLcode Curl_async_take_result(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                struct Curl_dns_entry **pdns)
{
  struct async_thrdd_ctx *thrdd = &async->thrdd;
  struct Curl_dns_entry *dns = NULL;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(pdns);
  *pdns = NULL;
  if(!async->queries_ongoing && !async->done) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }

#ifdef USE_HTTPSRR_ARES
  /* best effort, ignore errors */
  if(thrdd->rr.channel)
    (void)Curl_ares_perform(thrdd->rr.channel, 0);
#endif

  if(!async->done)
    return CURLE_AGAIN;

  Curl_expire_done(data, EXPIRE_ASYNC_NAME);
  if(async->result) {
    result = async->result;
    goto out;
  }

  if((thrdd->res_A && thrdd->res_A->res) ||
     (thrdd->res_AAAA && thrdd->res_AAAA->res)) {
    dns = Curl_dnscache_mk_entry2(
      data, async->dns_queries,
      thrdd->res_A ? &thrdd->res_A->res : NULL,
      thrdd->res_AAAA ? &thrdd->res_AAAA->res : NULL,
      async->hostname, async->port);
    if(!dns) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }

#ifdef USE_HTTPSRR_ARES
    if(thrdd->rr.channel) {
      struct Curl_https_rrinfo *lhrr = NULL;
      if(thrdd->rr.hinfo.complete) {
        lhrr = Curl_httpsrr_dup_move(&thrdd->rr.hinfo);
        if(!lhrr) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }
      }
      Curl_httpsrr_trace(data, lhrr);
      Curl_dns_entry_set_https_rr(dns, lhrr);
    }
#endif
  }

  if(dns) {
    *pdns = dns;
    dns = NULL;
  }
#ifdef CURLVERBOSE
  Curl_thrdq_trace(data->multi->resolv_thrdq, data);
#endif

out:
  Curl_dns_entry_unlink(data, &dns);
  Curl_async_thrdd_shutdown(data, async);
  if(!result && !*pdns)
    result = Curl_async_failed(data, async, NULL);
  if(result &&
     (result != CURLE_COULDNT_RESOLVE_HOST) &&
     (result != CURLE_COULDNT_RESOLVE_PROXY)) {
    CURL_TRC_DNS(data, "Error %d resolving %s:%d",
                 result, async->hostname, async->port);
  }
  return result;
}

static const struct Curl_addrinfo *async_thrdd_get_ai(
  const struct Curl_addrinfo *ai,
  int ai_family, unsigned int index)
{
  unsigned int i = 0;
  for(i = 0; ai; ai = ai->ai_next) {
    if(ai->ai_family == ai_family) {
      if(i == index)
        return ai;
      ++i;
    }
  }
  return NULL;
}

const struct Curl_addrinfo *Curl_async_get_ai(struct Curl_easy *data,
                                              struct Curl_resolv_async *async,
                                              int ai_family,
                                              unsigned int index)
{
  struct async_thrdd_ctx *thrdd = &async->thrdd;

  (void)data;
  switch(ai_family) {
  case AF_INET:
    if(thrdd->res_A)
      return async_thrdd_get_ai(thrdd->res_A->res, ai_family, index);
    break;
  case AF_INET6:
    if(thrdd->res_AAAA)
      return async_thrdd_get_ai(thrdd->res_AAAA->res, ai_family, index);
    break;
  default:
    break;
  }
  return NULL;
}

#ifdef USE_HTTPSRR
const struct Curl_https_rrinfo *Curl_async_get_https(
  struct Curl_easy *data,
  struct Curl_resolv_async *async)
{
#ifdef USE_HTTPSRR_ARES
  if(Curl_async_knows_https(data, async))
    return &async->thrdd.rr.hinfo;
#else
  (void)data;
  (void)async;
#endif
  return NULL;
}

bool Curl_async_knows_https(struct Curl_easy *data,
                            struct Curl_resolv_async *async)
{
  (void)data;
  if(async->dns_queries & CURL_DNSQ_HTTPS)
    return ((async->dns_responses & CURL_DNSQ_HTTPS) || async->done);
  return TRUE; /* we know it will never come */
}

#endif /* USE_HTTPSRR */

#endif /* USE_RESOLV_THREADED */
