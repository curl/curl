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
#include "progress.h"

static CURLcode t1399_setup(struct Curl_easy **easy)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t1399_stop(struct Curl_easy *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

/*
 * Invoke Curl_pgrsTime for TIMER_STARTSINGLE to trigger the behavior that
 * manages startransfer, but fake the startsingle_us time for purposes
 * of the test.
 */
static void fake_t_startsingle_time(struct Curl_easy *data,
                                    int seconds_offset)
{
  Curl_pgrsTime(data, TIMER_STARTSINGLE);
  data->progress.delta.startsingle_us = (seconds_offset * 1000 * 1000);
}

static bool usec_matches_seconds(timediff_t time_usec, int expected_seconds)
{
  static int usec_magnitude = 1000000;

  int time_sec = (int)(time_usec / usec_magnitude);
  bool same = (time_sec == expected_seconds);
  curl_mfprintf(stderr, "is %d us same as %d seconds? %s\n",
                (int)time_usec, expected_seconds,
                same ? "Yes" : "No");
  return same;
}

static void expect_timer_seconds(struct Curl_easy *data, int seconds)
{
  struct Progress *p = &data->progress;
  char msg[64];
  curl_msnprintf(msg, sizeof(msg), "about %d seconds should have passed",
                 seconds);
  fail_unless(usec_matches_seconds(p->total.nslookup_us, seconds), msg);
  fail_unless(usec_matches_seconds(p->total.connect_us, seconds), msg);
  fail_unless(usec_matches_seconds(p->total.appconnect_us, seconds), msg);
  fail_unless(usec_matches_seconds(p->total.pretransfer_us, seconds), msg);
  fail_unless(usec_matches_seconds(p->total.starttransfer_us, seconds), msg);
}

/* Scenario: simulate a redirect. When a redirect occurs, t_nslookup,
 * t_connect, t_appconnect, t_pretransfer, and t_starttransfer are additive.
 * E.g., if t_starttransfer took 2 seconds initially and took another 1
 * second for the redirect request, then the resulting t_starttransfer should
 * be 3 seconds. */
static CURLcode test_unit1399(const char *arg)
{
  struct Curl_easy *data;
  struct curltime now = curlx_now();

  UNITTEST_BEGIN(t1399_setup(&data))

  data->multi = NULL;
  data->progress.now = now;
  memset(&data->progress.delta, 0, sizeof(data->progress.delta));
  memset(&data->progress.total, 0, sizeof(data->progress.total));

  data->progress.start.tv_sec = now.tv_sec - 2;
  data->progress.start.tv_usec = now.tv_usec;
  fake_t_startsingle_time(data, 0);

  Curl_pgrsTime(data, TIMER_NAMELOOKUP);
  Curl_pgrsTime(data, TIMER_CONNECT);
  Curl_pgrsTime(data, TIMER_APPCONNECT);
  Curl_pgrsTime(data, TIMER_PRETRANSFER);
  Curl_pgrsTime(data, TIMER_STARTTRANSFER);

  expect_timer_seconds(data, 2);

  /* now simulate the redirect */
  data->progress.delta.startredirect_us = 1 * 1000 * 1000;
  fake_t_startsingle_time(data, 1);

  Curl_pgrsTime(data, TIMER_NAMELOOKUP);
  Curl_pgrsTime(data, TIMER_CONNECT);
  Curl_pgrsTime(data, TIMER_APPCONNECT);
  Curl_pgrsTime(data, TIMER_PRETRANSFER);
  /* ensure t_starttransfer is only set on the first invocation by attempting
   * to set it twice */
  Curl_pgrsTime(data, TIMER_STARTTRANSFER);
  Curl_pgrsTime(data, TIMER_STARTTRANSFER);

  expect_timer_seconds(data, 3);

  UNITTEST_END(t1399_stop(data))
}
