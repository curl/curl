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
#ifdef CURLRES_THREADED

#include "socketpair.h"

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
#include "thrdqueue.h"
#include "url.h"
#include "multiif.h"
#include "progress.h"
#include "rand.h"
#include "select.h"
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
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints;
#endif
#ifdef CURLVERBOSE
  char description[CURL_ASYN_ITEM_DESC_LEN];
#endif
  struct curltime start;
  int sock_error;
  curl_off_t conn_id;
  uint32_t mid;
  uint16_t port;
  uint8_t ip_version;
#ifdef DEBUGBUILD
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
static struct async_thrdd_item *
async_thrdd_item_create(struct Curl_easy *data,
                        const char *hostname, uint16_t port,
                        uint8_t ip_version)
{
  size_t hostlen = strlen(hostname);
  struct async_thrdd_item *item;
  VERBOSE(const char *qtype = "A");

  item = curlx_calloc(1, sizeof(*item) + hostlen);
  if(!item)
    return NULL;

  if(hostlen) /* NUL byte of name already in struct size */
    memcpy(item->hostname, hostname, hostlen);
  item->port = port;
  item->ip_version = ip_version;
  item->mid = data->mid;
  item->conn_id = data->conn ? data->conn->connection_id : -1;

#ifdef HAVE_GETADDRINFO
  {
    int pf = PF_INET;
#ifdef CURLRES_IPV6
    if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
      /* The stack seems to be IPv6-enabled */
      if(ip_version == CURL_IPRESOLVE_V6)
        pf = PF_INET6;
      else
        pf = PF_UNSPEC;
    }
#endif /* CURLRES_IPV6 */
    item->hints.ai_family = pf;
    item->hints.ai_socktype =
      (Curl_conn_get_transport(data, data->conn) == TRNSPRT_TCP) ?
      SOCK_STREAM : SOCK_DGRAM;
#ifdef CURLVERBOSE
    qtype = (pf == PF_INET6) ? "AAAA" : "A+AAAA";
#endif
  }
#endif /* HAVE_GETADDRINFO */

#ifdef CURLVERBOSE
  curl_msnprintf(item->description, sizeof(item->description),
                 "[%" FMT_OFF_T "-%" FMT_OFF_T "] %s %s:%u",
                 data->id, item->conn_id, qtype, item->hostname, item->port);
#endif

#ifdef DEBUGBUILD
  {
    const char *p = getenv("CURL_DBG_RESOLV_FAIL_DELAY");
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

CURLcode Curl_async_get_impl(struct Curl_easy *data,
                             struct Curl_resolv_async *async,
                             void **impl)
{
  (void)data;
  (void)async;
  *impl = NULL;
  return CURLE_OK;
}

#ifdef USE_HTTPSRR_ARES

static void async_thrdd_rr_done(void *user_data, ares_status_t status,
                                size_t timeouts,
                                const ares_dns_record_t *dnsrec)
{
  struct Curl_easy *data = user_data;
  struct Curl_resolv_async *async = data->state.async;

  (void)timeouts;
  if(!async)
    return;
  async->thrdd.rr.done = TRUE;
  if((ARES_SUCCESS != status) || !dnsrec)
    return;
  async->thrdd.rr.result = Curl_httpsrr_from_ares(data, dnsrec,
                                                  &async->thrdd.rr.hinfo);
}

static CURLcode async_rr_start(struct Curl_easy *data,
                               struct Curl_resolv_async *async)
{
  struct async_thrdd_ctx *thrdd = &async->thrdd;
  int status;
  char *rrname = NULL;

  DEBUGASSERT(!thrdd->rr.channel);
  if(async->port != 443) {
    rrname = curl_maprintf("_%d_.https.%s",
                           async->port, data->conn->host.name);
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
  thrdd->rr.hinfo.port = -1;
  thrdd->rr.hinfo.rrname = rrname;
  ares_query_dnsrec(thrdd->rr.channel,
                    rrname ? rrname : data->conn->host.name, ARES_CLASS_IN,
                    ARES_REC_TYPE_HTTPS,
                    async_thrdd_rr_done, data, NULL);
  CURL_TRC_DNS(data, "Issued HTTPS-RR request for %s", data->conn->host.name);
  return CURLE_OK;
}
#endif

/*
 * Until we gain a way to signal the resolver threads to stop early, we must
 * simply wait for them and ignore their results.
 */
void Curl_async_thrdd_shutdown(struct Curl_easy *data,
                              struct Curl_resolv_async *async)
{
  Curl_async_thrdd_destroy(data, async);
}

static bool async_thrdd_match_item(void *qitem, void *match_data)
{
  struct Curl_easy *data = match_data;
  struct async_thrdd_item *item = qitem;
  return item->mid == data->mid;
}

void Curl_async_thrdd_destroy(struct Curl_easy *data,
                              struct Curl_resolv_async *async)
{
  (void)data;
  if(async->thrdd.queued && !async->thrdd.done &&
     data->multi && data->multi->resolv_thrdq) {
    /* Remove any resolve items still queued */
    Curl_thrdq_clear(data->multi->resolv_thrdq,
                     async_thrdd_match_item, data);
  }
#ifdef USE_HTTPSRR_ARES
  if(async->thrdd.rr.channel) {
    ares_destroy(async->thrdd.rr.channel);
    async->thrdd.rr.channel = NULL;
  }
  Curl_httpsrr_cleanup(&async->thrdd.rr.hinfo);
#endif
  async_thrdd_item_destroy(async->thrdd.resolved);
  async->thrdd.resolved = NULL;
}

/*
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 */
CURLcode Curl_async_await(struct Curl_easy *data,
                          struct Curl_resolv_async *async,
                          struct Curl_dns_entry **pdns)
{
  struct async_thrdd_ctx *thrdd = &async->thrdd;
  timediff_t milli, ms;

  CURL_TRC_DNS(data, "[async] await %s", async->hostname);
  while(thrdd->queued && !thrdd->done) {
    Curl_async_thrdd_multi_process(data->multi);
    if(thrdd->done)
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
    CURL_TRC_DNS(data, "[async] await, waiting %" FMT_TIMEDIFF_T "ms",
                 milli);
    curlx_wait_ms(milli);
  }
  return Curl_async_take_result(data, async, pdns);
}

#ifdef HAVE_GETADDRINFO

/* Process the item, using Curl_getaddrinfo_ex() */
static void async_thrdd_item_process(void *arg)
{
  struct async_thrdd_item *item = arg;
  char service[12];
  int rc;

#ifdef DEBUGBUILD
    if(item->delay_fail_ms) {
      curlx_wait_ms(item->delay_fail_ms);
      return;
    }
#endif
  curl_msnprintf(service, sizeof(service), "%d", item->port);

  rc = Curl_getaddrinfo_ex(item->hostname, service,
                           &item->hints, &item->res);
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
static void async_thrdd_item_process(void *item)
{
  struct async_thrdd_item *item = arg;

#ifdef DEBUGBUILD
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
  DEBUGASSERT(!multi->resolv_thrdq);
  return Curl_thrdq_create(&multi->resolv_thrdq, "async", 0,
                           min_threads, max_threads, idle_time_ms,
                           async_thrdd_item_free,
                           async_thrdd_item_process,
                           async_thrdd_event,
                           multi);
}

/* Tear down the thread queue, joining active threads or detaching them */
void Curl_async_thrdd_multi_destroy(struct Curl_multi *multi, bool join)
{
  if(multi->resolv_thrdq) {
    Curl_thrdq_destroy(multi->resolv_thrdq, join);
    multi->resolv_thrdq = NULL;
  }
}

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

    CURL_TRC_DNS(multi->admin, "[async] got %s'%s'",
                 item->res ? "" : "negative for ", item->description);

    data = Curl_multi_get_easy(multi, item->mid);
    /* there is a chance the `mid` gets reused after a while, but the
     * connection id is not */
    if(data && data->conn && data->state.async &&
       (data->conn->connection_id == item->conn_id)) {
      struct Curl_resolv_async *async = data->state.async;

      async->thrdd.resolved = item;
      async->thrdd.done = TRUE;
      item = NULL;
      Curl_multi_mark_dirty(data);
    }
    async_thrdd_item_free(item);
  }
#ifdef CURLVERBOSE
  Curl_thrdq_trace(multi->resolv_thrdq, multi->admin, &Curl_trc_feat_dns);
#endif
}

CURLcode Curl_async_getaddrinfo(struct Curl_easy *data,
                                struct Curl_resolv_async *async)
{
  struct async_thrdd_item *item;
  CURLcode result;

  if(async->thrdd.queued || async->thrdd.done || async->thrdd.resolved)
    return CURLE_FAILED_INIT;

  item = async_thrdd_item_create(data, async->hostname, async->port,
                                 async->ip_version);
  if(!item) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  CURL_TRC_DNS(data, "[async] queueing %s", item->description);
  result = Curl_thrdq_send(data->multi->resolv_thrdq, item,
                           async_item_description(item));
  if(!result) {
    item = NULL;
    async->thrdd.queued = TRUE;
  }

#ifdef USE_HTTPSRR_ARES
  DEBUGASSERT(!async->thrdd.rr.channel);
  if(async_rr_start(data, async))
    infof(data, "Failed HTTPS RR operation");
#endif

out:
  if(item)
    async_thrdd_item_free(item);
  if(result)
    CURL_TRC_DNS(data, "[async] error queueing %s:%d -> %d",
                 async->hostname, async->port, result);
  return result;
}

CURLcode Curl_async_pollset(struct Curl_easy *data, struct easy_pollset *ps)
{
  struct Curl_resolv_async *async = data->state.async;
  struct async_thrdd_ctx *thrdd = async ? &async->thrdd : NULL;

  if(!thrdd)
    return CURLE_FAILED_INIT;
#ifdef USE_HTTPSRR_ARES
  if(thrdd->rr.channel) {
    CURLcode result = Curl_ares_pollset(data, thrdd->rr.channel, ps);
    if(result)
      return result;
  }
#else
  (void)ps;
#endif

  if(!thrdd->done) {
#ifdef ENABLE_WAKEUP
    /* The multi "wakeup" socket pair triggers result processing,
     * no need for an extra timer. */
  (void)data;
#else
    timediff_t milli;
    timediff_t ms = curlx_ptimediff_ms(Curl_pgrs_now(data), &async->start);
    if(ms < 3)
      milli = 1;
    else if(ms <= 50)
      milli = ms / 3;
    else if(ms <= 250)
      milli = 50;
    else
      milli = 200;
    Curl_expire(data, milli, EXPIRE_ASYNC_NAME);
#endif
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
  CURLcode result = CURLE_OK;

  DEBUGASSERT(pdns);
  *pdns = NULL;
  if(!thrdd->queued) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }

#ifdef USE_HTTPSRR_ARES
  /* best effort, ignore errors */
  if(thrdd->rr.channel)
    (void)Curl_ares_perform(thrdd->rr.channel, 0);
#endif

  if(!thrdd->done) {
    CURL_TRC_DNS(data, "[async] take %s:%d -> EAGAIN",
                 async->hostname, async->port);
    return CURLE_AGAIN;
  }

  Curl_expire_done(data, EXPIRE_ASYNC_NAME);
  if(thrdd->resolved && thrdd->resolved->res) {
    struct Curl_dns_entry *dns =
      Curl_dns_entry_create(data, &thrdd->resolved->res,
                            async->hostname, async->port, async->ip_version);
    if(!dns)
      result = CURLE_OUT_OF_MEMORY;

#ifdef USE_HTTPSRR_ARES
    if(!result && thrdd->rr.channel) {
      result = thrdd->rr.result;
      if(!result) {
        struct Curl_https_rrinfo *lhrr;
        lhrr = Curl_httpsrr_dup_move(&thrdd->rr.hinfo);
        if(!lhrr)
          result = CURLE_OUT_OF_MEMORY;
        else
          dns->hinfo = lhrr;
      }
    }
#endif
    if(!result && dns) {
      CURL_TRC_DNS(data, "[async] resolved: %s",
                   thrdd->resolved->description);
      *pdns = dns;
      dns = NULL;
    }
    Curl_dns_entry_unlink(data, &dns);
  }

  if(!result && !*pdns)
    result = Curl_resolver_error(data, NULL);
  Curl_async_thrdd_shutdown(data, async);
  if(result &&
     (result != CURLE_COULDNT_RESOLVE_HOST) &&
     (result != CURLE_COULDNT_RESOLVE_PROXY)) {
    CURL_TRC_DNS(data, "[async] %s:%d: error %d",
                 async->hostname, async->port, result);
  }
  return result;
}

#endif /* CURLRES_THREADED */
