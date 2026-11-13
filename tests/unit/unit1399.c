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

static bool usec_matches(timediff_t time_usec, timediff_t expected_usec)
{
  bool same = (time_usec == expected_usec);
  curl_mfprintf(stderr, "is %" FMT_TIMEDIFF_T
                " us same as %" FMT_TIMEDIFF_T " us? %s\n",
                time_usec, expected_usec, same ? "Yes" : "No");
  return same;
}

static void expect_timer_microseconds(struct Curl_easy *data,
                                      timediff_t microseconds)
{
  struct Progress *p = &data->progress;
  char msg[64];
  curl_msnprintf(msg, sizeof(msg),
                 "%" FMT_TIMEDIFF_T " microseconds should have passed",
                 microseconds);
  fail_unless(usec_matches(p->total.nslookup_us, microseconds), msg);
  fail_unless(usec_matches(p->total.connect_us, microseconds), msg);
  fail_unless(usec_matches(p->total.appconnect_us, microseconds), msg);
  fail_unless(usec_matches(p->total.pretransfer_us, microseconds), msg);
  fail_unless(usec_matches(p->total.starttransfer_us, microseconds), msg);
}

/* Scenario: simulate a redirect. When a redirect occurs, t_nslookup,
 * t_connect, t_appconnect, t_pretransfer, and t_starttransfer are additive.
 * E.g., if t_starttransfer took 2.25 seconds initially and took another 1.5
 * seconds for the redirect request, then the resulting t_starttransfer should
 * be 3.75 seconds. */
static CURLcode test_unit1399(const char *arg)
{
  struct Curl_easy *data;
  struct curltime now;

  UNITTEST_BEGIN(t1399_setup(&data))

  data->multi = NULL;
  now.tv_sec = 12345678;
  now.tv_usec = 0;
  data->progress.now = now;
  Curl_pgrsStart(data, &now);

  /* Record the first request start */
  Curl_pgrsTimeWas(data, TIMER_STARTSINGLE, now);
  /* Let 2.25 seconds pass */
  now.tv_sec += 2;
  now.tv_usec = 250000;
  Curl_pgrsTimeWas(data, TIMER_NAMELOOKUP, now);
  Curl_pgrsTimeWas(data, TIMER_CONNECT, now);
  Curl_pgrsTimeWas(data, TIMER_APPCONNECT, now);
  Curl_pgrsTimeWas(data, TIMER_PRETRANSFER, now);
  Curl_pgrsTimeWas(data, TIMER_STARTTRANSFER, now);

  expect_timer_microseconds(data, 2250000);

  /* now simulate the redirect after one second
   * and subsequent follow request start */
  now.tv_sec += 1;
  Curl_pgrsTimeWas(data, TIMER_REDIRECT, now);
  Curl_pgrsTimeWas(data, TIMER_STARTSINGLE, now);

  /* Let 1.5 seconds pass */
  now.tv_sec += 1;
  now.tv_usec = 750000;
  Curl_pgrsTimeWas(data, TIMER_NAMELOOKUP, now);
  Curl_pgrsTimeWas(data, TIMER_CONNECT, now);
  Curl_pgrsTimeWas(data, TIMER_APPCONNECT, now);
  Curl_pgrsTimeWas(data, TIMER_PRETRANSFER, now);
  Curl_pgrsTimeWas(data, TIMER_STARTTRANSFER, now);
  /* ensure t_starttransfer is only set on the first invocation by attempting
   * to set it twice */
  now.tv_sec += 1;
  Curl_pgrsTimeWas(data, TIMER_STARTTRANSFER, now);
  Curl_pgrsTimeWas(data, TIMER_STARTTRANSFER, now);

  /* Accumulated times are now 3.75 seconds:
   * - 2.25 after 1st request start
   * - 1.5 after 2nd request start */
  expect_timer_microseconds(data, 3750000);

  UNITTEST_END(t1399_stop(data))
}
