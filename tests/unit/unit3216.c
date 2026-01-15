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

#include "ratelimit.h"

static CURLcode test_unit3216(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct Curl_rlimit r;
  struct curltime ts;

  /* A ratelimit that is unlimited */
  ts = curlx_now();
  Curl_rlimit_init(&r, 0, 0, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == CURL_OFF_T_MAX, "inf");
  Curl_rlimit_drain(&r, 1000000, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == CURL_OFF_T_MAX, "drain keep inf");
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 0, "inf never waits");

  Curl_rlimit_block(&r, TRUE, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 0, "inf blocked to 0");
  Curl_rlimit_drain(&r, 1000000, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 0, "blocked inf");
  Curl_rlimit_block(&r, FALSE, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == CURL_OFF_T_MAX,
              "unblocked unlimited");

  /* A ratelimit that give 10 tokens per second */
  ts = curlx_now();
  Curl_rlimit_init(&r, 10, 0, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 10, "initial 10");
  Curl_rlimit_drain(&r, 5, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 5, "drain to 5");
  Curl_rlimit_drain(&r, 3, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 2, "drain to 2");
  ts.tv_usec += 1000; /* 1ms */
  Curl_rlimit_drain(&r, 3, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == -1, "drain to -1");
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 1099, "wait 1099ms");
  ts.tv_usec += 1000; /* 1ms */
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 1098, "wait 1098ms");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 9, "10 inc per sec");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 19, "10 inc per sec(2)");

  ts = curlx_now();
  Curl_rlimit_block(&r, TRUE, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 0, "10 blocked to 0");
  Curl_rlimit_block(&r, FALSE, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 10, "unblocked 10");

  /* A ratelimit that give 10 tokens per second, max burst 15/s */
  ts = curlx_now();
  Curl_rlimit_init(&r, 10, 15, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 10, "initial 10");
  Curl_rlimit_drain(&r, 5, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 5, "drain to 5");
  Curl_rlimit_drain(&r, 3, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 2, "drain to 2");
  Curl_rlimit_drain(&r, 3, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == -1, "drain to -1");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 9, "10 inc per sec");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 15, "10/15 burst limit");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 15, "10/15 burst limit(2)");
  Curl_rlimit_drain(&r, 15, &ts);
  fail_unless(Curl_rlimit_avail(&r, &ts) == 0, "drain to 0");
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 1000, "wait 1 sec");
  ts.tv_usec += 500000; /* half a sec, cheating on second carry */
  fail_unless(Curl_rlimit_avail(&r, &ts) == 0, "0 after 0.5 sec");
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 500, "wait 0.5 sec");
  ts.tv_sec += 1;
  fail_unless(Curl_rlimit_avail(&r, &ts) == 10, "10 after 1.5 sec");
  fail_unless(Curl_rlimit_wait_ms(&r, &ts) == 0, "wait 0");
  ts.tv_usec += 500000; /* half a sec, cheating on second carry */
  fail_unless(Curl_rlimit_avail(&r, &ts) == 15, "10 after 2 sec");

  UNITTEST_END_SIMPLE
}
