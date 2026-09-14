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
#include "urldata.h"
#include "multiif.h"

#define T3230_TIMER_CALLS 6

struct t3230_timer_ctx {
  long timeout_ms[T3230_TIMER_CALLS];
  size_t count;
};

static int t3230_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
  struct t3230_timer_ctx *ctx = userp;
  (void)multi;

  if(ctx->count < CURL_ARRAYSIZE(ctx->timeout_ms))
    ctx->timeout_ms[ctx->count] = timeout_ms;
  ++ctx->count;
  return 0;
}

static CURLcode t3230_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

static void t3230_test_timer_updates(void)
{
  CURLM *handle = curl_multi_init();
  struct Curl_multi *multi = handle;
  struct t3230_timer_ctx ctx;
  struct curltime now;
  timediff_t expire_offset_us;
  CURLMcode mresult;
  int running;

  memset(&ctx, 0, sizeof(ctx));
  if(!multi) {
    fail("multi handle creation failed");
    return;
  }

  mresult = curl_multi_setopt(handle, CURLMOPT_TIMERDATA, &ctx);
  fail_unless(mresult == CURLM_OK, "setting timer data failed");
  mresult = curl_multi_setopt(handle, CURLMOPT_TIMERFUNCTION,
                              t3230_timer_cb);
  fail_unless(mresult == CURLM_OK, "setting timer callback failed");

  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "initial timer update failed");
  fail_unless(!ctx.count, "callback invoked without a timeout");
  fail_unless(!multi->last_timeout_set, "initial timer marked as set");

  now = curlx_now();
  Curl_expire_set(multi->admin, EXPIRE_TIMEOUT, 600000, &now);
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "setting timer failed");
  fail_unless(ctx.count == 1, "setting timer did not invoke callback");
  fail_unless(multi->last_timeout_set, "timer not marked as set");

  Curl_expire_set(multi->admin, EXPIRE_TIMEOUT, 1200000, &now);
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "replacing timer failed");
  fail_unless(ctx.count == 2, "replacing timer did not invoke callback");

  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "unchanged timer update failed");
  fail_unless(ctx.count == 2, "unchanged timer invoked callback");

  expire_offset_us = multi->last_expire_offset_us;
  mresult = curl_multi_socket_action(handle, CURL_SOCKET_TIMEOUT, 0, &running);
  fail_unless(mresult == CURLM_OK, "forced timer refresh failed");
  fail_unless(ctx.count == 3, "timer refresh did not invoke callback");
  fail_unless(multi->last_expire_offset_us == expire_offset_us,
              "timer refresh changed expiry offset");
  fail_unless(multi->last_timeout_set, "refreshed timer not marked as set");

  Curl_expire_clear_all(multi->admin);
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "timer clear update failed");
  fail_unless(ctx.count == 4, "clearing timer did not invoke callback");
  fail_unless(!multi->last_timeout_set, "cleared timer marked as set");
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "repeated timer clear update failed");

  Curl_multi_mark_dirty(multi->admin);
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "zero timer update failed");
  fail_unless(multi->last_timeout_set, "zero timer not marked as set");
  Curl_multi_clear_dirty(multi->admin);
  fail_unless(Curl_update_timer(multi) == CURLM_OK,
              "clearing zero timer failed");
  fail_unless(!multi->last_timeout_set, "zero timer clear left timer set");

  fail_unless(ctx.count == T3230_TIMER_CALLS, "wrong timer callback count");
  fail_unless(ctx.timeout_ms[0] >= 0, "wrong initial timeout");
  fail_unless(ctx.timeout_ms[1] > ctx.timeout_ms[0],
              "wrong replacement timeout");
  fail_unless(ctx.timeout_ms[2] >= 0, "wrong refreshed timeout");
  fail_unless(ctx.timeout_ms[3] == -1, "wrong cleared timeout");
  fail_unless(ctx.timeout_ms[4] == 0, "wrong zero timeout");
  fail_unless(ctx.timeout_ms[5] == -1, "wrong zero timeout clear");

  curl_multi_cleanup(handle);
}

static CURLcode test_unit3230(const char *arg)
{
  UNITTEST_BEGIN(t3230_setup())

  t3230_test_timer_updates();

  UNITTEST_END(curl_global_cleanup())
}
