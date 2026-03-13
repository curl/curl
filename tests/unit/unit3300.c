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
#include "unitcheck.h"

#include "curlx/wait.h"
#include "thrdpool.h"

#ifdef USE_THREADS

struct unit3300_ctx {
  uint32_t total;
  uint32_t taken;
  uint32_t returned;
};

static uint32_t unit3300_item = 23;
static uint32_t unit3300_delay_ms = 0;

static void unit3300_ctx_init(struct unit3300_ctx *ctx,
                              uint32_t total,
                              uint32_t delay_ms)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->total = total;
  unit3300_delay_ms = delay_ms;
}

static void *unit3300_take(void *user_data, const char **pdescription,
                           timediff_t *ptimeout_ms)
{
  struct unit3300_ctx *ctx = user_data;
  *pdescription = NULL;
  *ptimeout_ms = 0;
  if(ctx->taken < ctx->total) {
    ctx->taken++;
    return &unit3300_item;
  }
  return NULL;
}

static void unit3300_process(void *item)
{
  fail_unless(item == &unit3300_item, "process unexpected item");
  if(unit3300_delay_ms) {
    curlx_wait_ms(unit3300_delay_ms);
  }
}

static void unit3300_return(void *item, void *user_data)
{
  struct unit3300_ctx *ctx = user_data;
  (void)item;
  if(ctx) {
    ctx->returned++;
    fail_unless(ctx->returned <= ctx->total, "returned too many");
  }
}

static CURLcode test_unit3300(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct curl_thrdpool *tpool;
  struct unit3300_ctx ctx;
  CURLcode r;

  /* pool without minimum, will not start anything */
  unit3300_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3300a", 0, 2, 0,
                           unit3300_take, unit3300_process, unit3300_return,
                           &ctx);
  fail_unless(!r, "pool-a create");
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(!ctx.returned, "pool-a unexpected items returned");
  fail_unless(!ctx.taken, "pool-a unexpected items taken");

  /* pool without minimum, signal start, consumes everything */
  unit3300_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3300b", 0, 2, 0,
                           unit3300_take, unit3300_process, unit3300_return,
                           &ctx);
  fail_unless(!r, "pool-b create");
  r = Curl_thrdpool_signal(tpool, 2);
  fail_unless(!r, "pool-b signal");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-b items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-b items taken missing");

  /* pool with minimum, consumes everything without signal */
  unit3300_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3300c", 1, 2, 0,
                           unit3300_take, unit3300_process, unit3300_return,
                           &ctx);
  fail_unless(!r, "pool-c create");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-c items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-c items taken missing");

  /* pool with many max, signal abundance, consumes everything */
  unit3300_ctx_init(&ctx, 100, 0);
  r = Curl_thrdpool_create(&tpool, "unit3300d", 0, 50, 0,
                           unit3300_take, unit3300_process, unit3300_return,
                           &ctx);
  fail_unless(!r, "pool-d create");
  r = Curl_thrdpool_signal(tpool, 100);
  fail_unless(!r, "pool-d signal");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-d items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-d items taken missing");

  /* pool with 1 max, many to take, no await, destroy without join */
  unit3300_ctx_init(&ctx, 10000000, 1);
  r = Curl_thrdpool_create(&tpool, "unit3300e", 0, 1, 0,
                           unit3300_take, unit3300_process, unit3300_return,
                           &ctx);
  fail_unless(!r, "pool-e create");
  r = Curl_thrdpool_signal(tpool, 100);
  fail_unless(!r, "pool-e signal");
  Curl_thrdpool_destroy(tpool, FALSE);
  fail_unless(ctx.returned < ctx.total, "pool-e returned all");
  fail_unless(ctx.taken < ctx.total, "pool-e took all");
#ifdef DEBUGBUILD
  /* pool thread will notice destruction and should immediately abort.
   * No memory leak should be reported. if the wait is too short on
   * a slow system, thread sanitizer will freak out as memdebug will
   * be called by threads after main thread shut down. */
  curlx_wait_ms(1000);
#endif

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit3300(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  (void)arg;
  UNITTEST_END_SIMPLE
}
#endif /* USE_THREADS */
