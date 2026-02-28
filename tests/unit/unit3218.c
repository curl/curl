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
#include "thrdqueue.h"

#ifdef USE_THREADS

struct unit3218_item {
  int id;
  BIT(processed);
};

struct unit3218_ctx {
  int ndone;
};

static struct unit3218_item *unit3218_item_create(int id)
{
  struct unit3218_item *uitem;
  uitem = curlx_calloc(1, sizeof(*uitem));
  if(uitem) {
    uitem->id = id;
    curl_mfprintf(stderr, "created item %d\n", uitem->id);
  }
  return uitem;
}

static void unit3218_item_free(void *item)
{
  struct unit3218_item *uitem = item;
  curl_mfprintf(stderr, "free item %d\n", uitem->id);
  curlx_free(uitem);
}

static void unit3218_event(const struct curl_thrdq *tqueue,
                           Curl_thrdq_event ev,
                           void *user_data)
{
  struct unit3218_ctx *ctx = user_data;
  (void)tqueue;
  switch(ev) {
  case CURL_THRDQ_EV_ITEM_DONE:
    ctx->ndone++;
    break;
  default:
    break;
  }
}

static void unit3218_process(void *item)
{
  struct unit3218_item *uitem = item;
  curl_mfprintf(stderr, "start item %d\n", uitem->id);
  curlx_wait_ms(1);
  uitem->processed = TRUE;
  curl_mfprintf(stderr, "end item %d\n", uitem->id);
}

static CURLcode test_unit3218(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct curl_thrdq *tqueue;
  struct unit3218_ctx ctx;
  int i, count;
  CURLcode r;

  /* create and teardown queue */
  memset(&ctx, 0, sizeof(ctx));
  r = Curl_thrdq_create(&tqueue, "unit3218-a", 0, 0, 2, 1,
                        unit3218_item_free, unit3218_process, unit3218_event,
                        &ctx);
  fail_unless(!r, "queue-a create");
  Curl_thrdq_destroy(tqueue, TRUE);
  tqueue = NULL;
  fail_unless(!ctx.ndone, "queue-a unexpected done count");

  /* create queue, have it process `count` items */
  count = 10;
  memset(&ctx, 0, sizeof(ctx));
  r = Curl_thrdq_create(&tqueue, "unit3218-b", 0, 0, 2, 1,
                        unit3218_item_free, unit3218_process, unit3218_event,
                        &ctx);
  fail_unless(!r, "queue-b create");
  for(i = 0; i < count; ++i) {
    struct unit3218_item *uitem = unit3218_item_create(i);
    fail_unless(uitem, "queue-b item create");
    r = Curl_thrdq_send(tqueue, uitem, NULL, 0);
    fail_unless(!r, "queue-b send");
  }

  r = Curl_thrdq_await_done(tqueue, 0);
  fail_unless(!r, "queue-b await done");

  for(i = 0; i < count; ++i) {
    void *item;
    r = Curl_thrdq_recv(tqueue, &item);
    fail_unless(!r, "queue-b recv");
    if(item) {
      struct unit3218_item *uitem = item;
      fail_unless(uitem->processed, "queue-b recv unprocessed item");
      unit3218_item_free(item);
    }
  }
  Curl_thrdq_destroy(tqueue, TRUE);
  tqueue = NULL;
  fail_unless(ctx.ndone == count, "queue-b unexpected done count");

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit3218(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  (void)arg;
  UNITTEST_END_SIMPLE
}
#endif /* USE_THREADS */
