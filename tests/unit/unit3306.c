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
#include "curl_threads.h"

#if defined(USE_THREADS) && defined(DEBUGBUILD)

struct unit3306_item {
  int id;
  BIT(processed);
};

static struct unit3306_item *unit3306_item_create(int id)
{
  struct unit3306_item *uitem;
  uitem = curlx_calloc(1, sizeof(*uitem));
  if(uitem) {
    uitem->id = id;
    curl_mfprintf(stderr, "created item %d\n", uitem->id);
  }
  return uitem;
}

static void unit3306_item_free(void *item)
{
  struct unit3306_item *uitem = item;
  curl_mfprintf(stderr, "free item %d\n", uitem->id);
  curlx_free(uitem);
}

static void unit3306_process(void *item)
{
  struct unit3306_item *uitem = item;
  curlx_wait_ms(1);
  uitem->processed = TRUE;
}

/* The test runs with CURL_DBG_THRDPOOL_FAIL_STARTS=5 set, making the
 * pool's first 5 thread starts fail, as if the system temporarily ran
 * against a thread limit. Each of the 3 sends attempts one thread
 * start (3 failures) and no thread exists to process the queue. Only
 * the receive side signalling the pool again - consuming the
 * remaining 2 armed failures, one per empty receive, and then
 * starting workers - lets the items get processed. */
static CURLcode test_unit3306(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct curl_thrdq *tqueue;
  int i, count = 3, nrecvd;
  CURLcode result;

  fail_unless(getenv("CURL_DBG_THRDPOOL_FAIL_STARTS"),
              "CURL_DBG_THRDPOOL_FAIL_STARTS must be set for this test");
  result = Curl_thrdq_create(&tqueue, "unit3306", 0, 2, 1,
                             unit3306_item_free, unit3306_process,
                             NULL, NULL);
  fail_unless(!result, "queue create");
  for(i = 0; i < count; ++i) {
    struct unit3306_item *uitem = unit3306_item_create(i);
    fail_unless(uitem, "item create");
    result = Curl_thrdq_send(tqueue, uitem, NULL, 0);
    fail_unless(!result, "send");
  }

  /* no send was able to start a thread. Receive until all items come
     back processed, which needs the recv side to signal the pool. */
  nrecvd = 0;
  for(i = 0; (nrecvd < count) && (i < 10000); ++i) {
    void *item;
    result = Curl_thrdq_recv(tqueue, &item);
    fail_unless(!result || (result == CURLE_AGAIN), "recv");
    if(item) {
      struct unit3306_item *uitem = item;
      curl_mfprintf(stderr, "received item %d\n", uitem->id);
      ++nrecvd;
      fail_unless(uitem->processed, "recv unprocessed item");
      unit3306_item_free(item);
    }
    else
      curlx_wait_ms(1);
  }
  Curl_thrdq_destroy(tqueue, TRUE);
  tqueue = NULL;
  fail_unless(nrecvd == count, "items not processed");

  UNITTEST_END_SIMPLE
}

#else
static CURLcode test_unit3306(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}
#endif /* USE_THREADS && DEBUGBUILD */
