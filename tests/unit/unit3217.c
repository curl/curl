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

struct unit3217_ctx {
  uint32_t total;
  uint32_t taken;
  uint32_t returned;
};

static uint32_t unit3217_item = 23;
static uint32_t unit3217_delay_ms = 0;

static void unit3217_ctx_init(struct unit3217_ctx *ctx,
                              uint32_t total,
                              uint32_t delay_ms)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->total = total;
  unit3217_delay_ms = delay_ms;
}

static void *unit3217_take(void *user_data)
{
  struct unit3217_ctx *ctx = user_data;
  if(ctx->taken < ctx->total) {
    ctx->taken++;
    return &unit3217_item;
  }
  return NULL;
}

static void unit3217_process(void *item)
{
  fail_unless(item == &unit3217_item, "process unexpected item");
  if(unit3217_delay_ms) {
    curlx_wait_ms(unit3217_delay_ms);
  }
}

static void unit3217_return(void *item, void *user_data)
{
  struct unit3217_ctx *ctx = user_data;
  (void)item;
  if(ctx) {
    ctx->returned++;
    fail_unless(ctx->returned <= ctx->total, "returned too many");
  }
}

static CURLcode test_unit3217(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct curl_thrdpool *tpool;
  struct unit3217_ctx ctx;
  CURLcode r;

  /* pool without minimum, will not start anything */
  unit3217_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3217a", 0, 2, 0,
                           unit3217_take, unit3217_process, unit3217_return,
                           &ctx);
  fail_unless(!r, "pool-a create");
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(!ctx.returned, "pool-a unexpected items returned");
  fail_unless(!ctx.taken, "pool-a unexpected items taken");

  /* pool without minimum, signal start, consumes everything */
  unit3217_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3217b", 0, 2, 0,
                           unit3217_take, unit3217_process, unit3217_return,
                           &ctx);
  fail_unless(!r, "pool-b create");
  r = Curl_thrdpool_signal(tpool, 2);
  fail_unless(!r, "pool-b signal");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-b items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-b items taken missing");

  /* pool with minimum, consumes everything without signal */
  unit3217_ctx_init(&ctx, 10, 0);
  r = Curl_thrdpool_create(&tpool, "unit3217c", 1, 2, 0,
                           unit3217_take, unit3217_process, unit3217_return,
                           &ctx);
  fail_unless(!r, "pool-c create");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-c items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-c items taken missing");

  /* pool with many max, signal abundance, consumes everything */
  unit3217_ctx_init(&ctx, 100, 0);
  r = Curl_thrdpool_create(&tpool, "unit3217d", 0, 50, 0,
                           unit3217_take, unit3217_process, unit3217_return,
                           &ctx);
  fail_unless(!r, "pool-d create");
  r = Curl_thrdpool_signal(tpool, 100);
  fail_unless(!r, "pool-d signal");
  Curl_thrdpool_await_idle(tpool, 0);
  Curl_thrdpool_destroy(tpool, TRUE);
  fail_unless(ctx.returned == ctx.total, "pool-d items returned missing");
  fail_unless(ctx.taken == ctx.total, "pool-d items taken missing");

  /* pool with 1 max, many to take, no await, destroy without join */
  unit3217_ctx_init(&ctx, 10000000, 1);
  r = Curl_thrdpool_create(&tpool, "unit3217e", 0, 1, 0,
                           unit3217_take, unit3217_process, unit3217_return,
                           &ctx);
  fail_unless(!r, "pool-e create");
  r = Curl_thrdpool_signal(tpool, 100);
  fail_unless(!r, "pool-e signal");
  Curl_thrdpool_destroy(tpool, FALSE);
  fail_unless(ctx.returned < ctx.total, "pool-e returned all");
  fail_unless(ctx.taken < ctx.total, "pool-e took all");
  /* pool thread will notice destruction and should immediately abort.
   * No memory leak should be reported. */
  curlx_wait_ms(1000);

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit3217(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  (void)arg;
  UNITTEST_END_SIMPLE
}
#endif /* USE_THREADS */
