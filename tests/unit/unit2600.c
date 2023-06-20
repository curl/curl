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
#include "curlcheck.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
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

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "urldata.h"
#include "connect.h"
#include "cfilters.h"
#include "curl_log.h"

/* copied from hostip.c to switch using SIGALARM for timeouts.
 * SIGALARM has only seconds resolution, so our tests will not work
 * here. */
#if defined(CURLRES_SYNCH) && \
    defined(HAVE_ALARM) && defined(SIGALRM) && defined(HAVE_SIGSETJMP)
#define USE_ALARM_TIMEOUT
#endif


static CURL *easy;

static CURLcode unit_setup(void)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  return res;
}

static void unit_stop(void)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

#ifdef DEBUGBUILD

struct test_case {
  int id;
  const char *url;
  const char *resolve_info;
  unsigned char ip_version;
  timediff_t connect_timeout_ms;
  timediff_t he_timeout_ms;
  timediff_t cf4_fail_delay_ms;
  timediff_t cf6_fail_delay_ms;

  int exp_cf4_creations;
  int exp_cf6_creations;
  timediff_t min_duration_ms;
  timediff_t max_duration_ms;
  CURLcode exp_result;
  const char *pref_family;
};

struct ai_family_stats {
  const char *family;
  int creations;
  timediff_t first_created;
  timediff_t last_created;
};

struct test_result {
  CURLcode result;
  struct curltime started;
  struct curltime ended;
  struct ai_family_stats cf4;
  struct ai_family_stats cf6;
};

static struct test_case *current_tc;
static struct test_result *current_tr;

struct cf_test_ctx {
  int ai_family;
  int transport;
  char id[16];
  struct curltime started;
  timediff_t fail_delay_ms;
  struct ai_family_stats *stats;
};

static void cf_test_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_test_ctx *ctx = cf->ctx;

  infof(data, "%04dms: cf[%s] destroyed",
       (int)Curl_timediff(Curl_now(), current_tr->started), ctx->id);
  free(ctx);
  cf->ctx = NULL;
}

static CURLcode cf_test_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool blocking, bool *done)
{
  struct cf_test_ctx *ctx = cf->ctx;
  struct curltime now;

  (void)data;
  (void)blocking;
  *done = FALSE;
  now = Curl_now();
  if(Curl_timediff(now, ctx->started) >= ctx->fail_delay_ms) {
    infof(data, "%04dms: cf[%s] fail delay reached",
         (int)Curl_timediff(Curl_now(), current_tr->started), ctx->id);
    return CURLE_COULDNT_CONNECT;
  }
  infof(data, "%04dms: cf[%s] continuing",
       (int)Curl_timediff(Curl_now(), current_tr->started), ctx->id);
  return CURLE_OK;
}

static struct Curl_cftype cft_test = {
  "TEST",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_DEFAULT,
  cf_test_destroy,
  cf_test_connect,
  Curl_cf_def_close,
  Curl_cf_def_get_host,
  Curl_cf_def_get_select_socks,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_test_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai,
                               int transport)
{
  struct cf_test_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  timediff_t created_at;
  CURLcode result;

  (void)data;
  (void)conn;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->ai_family = ai->ai_family;
  ctx->transport = transport;
  ctx->started = Curl_now();
#ifdef ENABLE_IPV6
  if(ctx->ai_family == AF_INET6) {
    ctx->stats = &current_tr->cf6;
    ctx->fail_delay_ms = current_tc->cf6_fail_delay_ms;
    curl_msprintf(ctx->id, "v6-%d", ctx->stats->creations);
    ctx->stats->creations++;
  }
  else
#endif
  {
    ctx->stats = &current_tr->cf4;
    ctx->fail_delay_ms = current_tc->cf4_fail_delay_ms;
    curl_msprintf(ctx->id, "v4-%d", ctx->stats->creations);
    ctx->stats->creations++;
  }

  created_at = Curl_timediff(ctx->started, current_tr->started);
  if(ctx->stats->creations == 1)
    ctx->stats->first_created = created_at;
  ctx->stats->last_created = created_at;
  infof(data, "%04dms: cf[%s] created", (int)created_at, ctx->id);

  result = Curl_cf_create(&cf, &cft_test, ctx);

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    free(cf);
    free(ctx);
  }
  return result;
}

static void check_result(struct test_case *tc,
                         struct test_result *tr)
{
  char msg[256];
  timediff_t duration_ms = 0;

  if(tr->result != tc->exp_result
    && CURLE_OPERATION_TIMEDOUT != tr->result) {
    /* on CI we encounter the TIMEOUT result, since images get less CPU
     * and events are not as sharply timed. */
    curl_msprintf(msg, "%d: expected result %d but got %d",
                  tc->id, tc->exp_result, tr->result);
    fail(msg);
  }
  if(tr->cf4.creations != tc->exp_cf4_creations) {
    curl_msprintf(msg, "%d: expected %d ipv4 creations, but got %d",
                  tc->id, tc->exp_cf4_creations, tr->cf4.creations);
    fail(msg);
  }
  if(tr->cf6.creations != tc->exp_cf6_creations) {
    curl_msprintf(msg, "%d: expected %d ipv6 creations, but got %d",
                  tc->id, tc->exp_cf6_creations, tr->cf6.creations);
    fail(msg);
  }

  (void)duration_ms;
#ifndef USE_ALARM_TIMEOUT
  duration_ms = Curl_timediff(tr->ended, tr->started);
  if(duration_ms < tc->min_duration_ms) {
    curl_msprintf(msg, "%d: expected min duration of %dms, but took %dms",
                  tc->id, (int)tc->min_duration_ms, (int)duration_ms);
    fail(msg);
  }
  if(duration_ms > tc->max_duration_ms) {
    curl_msprintf(msg, "%d: expected max duration of %dms, but took %dms",
                  tc->id, (int)tc->max_duration_ms, (int)duration_ms);
    fail(msg);
  }
#endif
  if(tr->cf6.creations && tr->cf4.creations && tc->pref_family) {
    /* did ipv4 and ipv6 both, expect the preferred family to start right arway
     * with the other being delayed by the happy_eyeball_timeout */
    struct ai_family_stats *stats1 = !strcmp(tc->pref_family, "v6")?
                                     &tr->cf6 : &tr->cf4;
    struct ai_family_stats *stats2 = !strcmp(tc->pref_family, "v6")?
                                     &tr->cf4 : &tr->cf6;

    if(stats1->first_created > 100) {
      curl_msprintf(msg, "%d: expected ip%s to start right away, instead "
                    "first attempt made after %dms",
                    tc->id, stats1->family, (int)stats1->first_created);
      fail(msg);
    }
#ifndef USE_ALARM_TIMEOUT
    if(stats2->first_created < tc->he_timeout_ms) {
#else
    if(stats2->first_created < 1000) {
#endif
      curl_msprintf(msg, "%d: expected ip%s to start delayed after %dms, "
                    "instead first attempt made after %dms",
                    tc->id, stats2->family, (int)tc->he_timeout_ms,
                    (int)stats2->first_created);
      fail(msg);
    }
  }
}

static void test_connect(struct test_case *tc)
{
  struct test_result tr;
  struct curl_slist *list = NULL;

  Curl_debug_set_transport_provider(TRNSPRT_TCP, cf_test_create);
  current_tc = tc;
  current_tr = &tr;

  list = curl_slist_append(NULL, tc->resolve_info);
  fail_unless(list, "error allocating resolve list entry");
  curl_easy_setopt(easy, CURLOPT_RESOLVE, list);
  curl_easy_setopt(easy, CURLOPT_IPRESOLVE, (long)tc->ip_version);
#ifdef USE_ALARM_TIMEOUT
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
  curl_easy_setopt(easy, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
                   (tc->he_timeout_ms > tc->connect_timeout_ms)?
                   3000L : 1000L);
#else
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS,
                   (long)tc->connect_timeout_ms);
  curl_easy_setopt(easy, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
                   (long)tc->he_timeout_ms);
#endif

  curl_easy_setopt(easy, CURLOPT_URL, tc->url);
  memset(&tr, 0, sizeof(tr));
  tr.cf6.family = "v6";
  tr.cf4.family = "v4";

  tr.started = Curl_now();
  tr.result = curl_easy_perform(easy);
  tr.ended = Curl_now();

  curl_easy_setopt(easy, CURLOPT_RESOLVE, NULL);
  curl_slist_free_all(list);
  list = NULL;
  current_tc = NULL;
  current_tr = NULL;

  check_result(tc, &tr);
}

#endif /* DEBUGBUILD */

/*
 * How these test cases work:
 * - replace the creation of the TCP socket filter with our test filter
 * - test filter does nothing and reports failure after configured delay
 * - we feed addresses into the resolve cache to simulate different cases
 * - we monitor how many instances of ipv4/v6 attempts are made and when
 * - for mixed families, we expect HAPPY_EYEBALLS_TIMEOUT to trigger
 *
 * Max Duration checks needs to be conservative since CI jobs are not
 * as sharp.
 */
#define TURL "http://test.com:123"

#define R_FAIL      CURLE_COULDNT_CONNECT

static struct test_case TEST_CASES[] = {
  /* TIMEOUT_MS,        FAIL_MS      CREATED    DURATION     Result, HE_PREF */
  /* CNCT   HE          v4    v6     v4 v6      MIN   MAX */
  { 1, TURL, "test.com:123:192.0.2.1", CURL_IPRESOLVE_WHATEVER,
    250,  150,        200,  200,    1,  0,      200,  600,  R_FAIL, NULL },
  /* 1 ipv4, fails after ~200ms, reports COULDNT_CONNECT   */
  { 2, TURL, "test.com:123:192.0.2.1,192.0.2.2", CURL_IPRESOLVE_WHATEVER,
    500,  150,        200,  200,    2,  0,      400,  800,  R_FAIL, NULL },
  /* 2 ipv4, fails after ~400ms, reports COULDNT_CONNECT   */
#ifdef ENABLE_IPV6
  { 3, TURL, "test.com:123:::1", CURL_IPRESOLVE_WHATEVER,
    250,  150,        200,  200,    0,  1,      200,  500,  R_FAIL, NULL },
  /* 1 ipv6, fails after ~200ms, reports COULDNT_CONNECT   */
  { 4, TURL, "test.com:123:::1,::2", CURL_IPRESOLVE_WHATEVER,
    500,  150,        200,  200,    0,  2,      400,  800,  R_FAIL, NULL },
  /* 2 ipv6, fails after ~400ms, reports COULDNT_CONNECT   */

  { 5, TURL, "test.com:123:192.0.2.1,::1", CURL_IPRESOLVE_WHATEVER,
    500,  150,        200, 200,     1,  1,      350,  800,  R_FAIL, "v4" },
  /* mixed ip4+6, v4 starts, v6 kicks in on HE, fails after ~350ms */
  { 6, TURL, "test.com:123:::1,192.0.2.1", CURL_IPRESOLVE_WHATEVER,
    500,  150,        200, 200,     1,  1,      350,  800,  R_FAIL, "v6" },
  /* mixed ip6+4, v6 starts, v4 kicks in on HE, fails after ~350ms */
  { 7, TURL, "test.com:123:::1,192.0.2.1,::2,::3", CURL_IPRESOLVE_WHATEVER,
    500,  600,        200, 200,     0,  3,      350,  800,  R_FAIL, "v6" },
  /* mixed ip6+4, v6 starts, v4 never starts due to high HE, TIMEOUT */
  { 8, TURL, "test.com:123:192.0.2.1,::1", CURL_IPRESOLVE_V4,
    400,  150,        500, 500,     1,  0,      400,  600,  R_FAIL, NULL },
  /* mixed ip4+6, but only use v4, check it uses full connect timeout,
     although another address of the 'wrong' family is available */
  { 9, TURL, "test.com:123:::1,192.0.2.1", CURL_IPRESOLVE_V6,
    400,  150,        500, 500,     0,  1,      400,  600,  R_FAIL, NULL },
  /* mixed ip4+6, but only use v6, check it uses full connect timeout,
     although another address of the 'wrong' family is available */
#endif
};

UNITTEST_START

#if defined(DEBUGBUILD)
  size_t i;

  for(i = 0; i < sizeof(TEST_CASES)/sizeof(TEST_CASES[0]); ++i) {
    test_connect(&TEST_CASES[i]);
  }
#else
  (void)TEST_CASES;
  (void)test_connect;
#endif

UNITTEST_STOP
