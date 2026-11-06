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
#include "connect.h"

static CURLcode t1303_setup(struct Curl_easy **easy)
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

static void t1303_stop(struct Curl_easy *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

/* BASE is a define to make us fool around with decently large number so
   that we are not zero-based */
#define BASE 1000000

/* macro to set the pretended current time */
#define NOW(x, y) \
  now.tv_sec = x; \
  now.tv_usec = y
/* macro to set the millisecond based timeouts to use */
#define TIMEOUTS(x, y)         \
  easy->set.timeout = x;       \
  easy->set.connecttimeout = y

/*
 * To test:
 *
 * 00/10/01/11 timeouts set
 * 0/1         during connect
 * T           various values on the timeouts
 * N           various values of now
 */

static CURLcode test_unit1303(const char *arg)
{
  struct Curl_easy *easy;

  UNITTEST_BEGIN(t1303_setup(&easy))

  struct curltime now;
  unsigned int i;

  struct timetest {
    int now_s;
    int now_us;
    unsigned int timeout_ms;
    unsigned int connecttimeout_ms;
    bool connecting;
    timediff_t result;
    const char *comment;
  };

  static const struct timetest run[] = {
    /* both timeouts set, not connecting */
    {BASE + 4, 0,      10000, 8000, FALSE, 6000, "6 seconds should be left"},
    {BASE + 4, 990000, 10000, 8000, FALSE, 5010, "5010 ms should be left"},
    {BASE + 10, 0,     10000, 8000, FALSE, -1,   "timeout is -1, expired"},
    {BASE + 12, 0,     10000, 8000, FALSE, -2000, "-2000, overdue 2 seconds"},

    /* both timeouts set, connecting */
    {BASE + 4, 0,      10000, 8000, TRUE, 4000, "4 seconds should be left"},
    {BASE + 4, 990000, 10000, 8000, TRUE, 3010, "3010 ms should be left"},
    {BASE + 8, 0,      10000, 8000, TRUE, -1,   "timeout is -1, expired"},
    {BASE + 10, 0,     10000, 8000, TRUE, -2000, "-2000, overdue 2 seconds"},

    /* no connect timeout set, not connecting */
    {BASE + 4, 0,      10000, 0, FALSE, 6000, "6 seconds should be left"},
    {BASE + 4, 990000, 10000, 0, FALSE, 5010, "5010 ms should be left"},
    {BASE + 10, 0,     10000, 0, FALSE, -1,   "timeout is -1, expired"},
    {BASE + 12, 0,     10000, 0, FALSE, -2000, "-2000, overdue 2 seconds"},

    /* no connect timeout set, connecting */
    {BASE + 4, 0,      10000, 0, TRUE, 6000, "6 seconds should be left"},
    {BASE + 4, 990000, 10000, 0, TRUE, 5010, "5010 ms should be left"},
    {BASE + 10, 0,     10000, 0, TRUE, -1,   "timeout is -1, expired"},
    {BASE + 12, 0,     10000, 0, TRUE, -2000, "-2000, overdue 2 seconds"},

    /* only connect timeout set, not connecting */
    {BASE + 4, 0,      0, 10000, FALSE, 0, "no timeout active"},
    {BASE + 4, 990000, 0, 10000, FALSE, 0, "no timeout active"},
    {BASE + 10, 0,     0, 10000, FALSE, 0, "no timeout active"},
    {BASE + 12, 0,     0, 10000, FALSE, 0, "no timeout active"},

    /* only connect timeout set, connecting */
    {BASE + 4, 0,      0, 10000, TRUE, 6000, "6 seconds should be left"},
    {BASE + 4, 990000, 0, 10000, TRUE, 5010, "5010 ms should be left"},
    {BASE + 10, 0,     0, 10000, TRUE, -1,   "timeout is -1, expired"},
    {BASE + 12, 0,     0, 10000, TRUE, -2000, "-2000, overdue 2 seconds"},

    /* no timeout set, not connecting */
    {BASE + 4, 0,      0, 0, FALSE, 0, "no timeout active"},
    {BASE + 4, 990000, 0, 0, FALSE, 0, "no timeout active"},
    {BASE + 10, 0,     0, 0, FALSE, 0, "no timeout active"},
    {BASE + 12, 0,     0, 0, FALSE, 0, "no timeout active"},

    /* no timeout set, connecting */
    {BASE + 4, 0,      0, 0, TRUE, 296000, "no timeout active"},
    {BASE + 4, 990000, 0, 0, TRUE, 295010, "no timeout active"},
    {BASE + 10, 0,     0, 0, TRUE, 290000, "no timeout active"},
    {BASE + 12, 0,     0, 0, TRUE, 288000, "no timeout active"},

    /* both timeouts set, connecting, connect timeout the longer one */
    {BASE + 4, 0,      10000, 12000, TRUE, 6000, "6 seconds should be left"},
  };

  /* this is the pretended start time of the transfer */
  easy->progress.start.tv_sec = BASE;
  easy->progress.start.tv_usec = 0;
  easy->progress.delta.startsingle_us = 0;
  easy->progress.delta.startop_us = 0;

  for(i = 0; i < CURL_ARRAYSIZE(run); i++) {
    timediff_t timeout;
    NOW(run[i].now_s, run[i].now_us);
    TIMEOUTS(run[i].timeout_ms, run[i].connecttimeout_ms);
    easy->progress.now = now;
    easy->mstate = run[i].connecting ? MSTATE_INIT : MSTATE_DO;
    timeout = timeleft_now_ms(easy, &now);
    if(timeout != run[i].result)
      fail(run[i].comment);
  }

  {
    struct timetest2 {
      int now_s;
      int now_us;
      unsigned int timeout_ms;
      unsigned int connecttimeout_ms;
      bool connecting;
      bool connect_only;
      bool total; /* Curl_timeleft_total_now_ms() instead of timeleft_now_ms */
      timediff_t result;
      const char *comment;
    };

    static const struct timetest2 run2[] = {
      /* the total variant ignores the connect timeout */
      {BASE + 4, 0,  10000, 8000, TRUE, FALSE, TRUE, 6000,
       "total: 6 seconds should be left while connecting"},
      {BASE + 9, 0,  10000, 8000, TRUE, FALSE, TRUE, 1000,
       "total: 1 second should be left, connect timeout ignored"},
      {BASE + 10, 0, 10000, 8000, TRUE, FALSE, TRUE, -1,
       "total: timeout is -1, expired"},
      {BASE + 4, 0,  0, 8000, TRUE, FALSE, TRUE, 0,
       "total: no overall timeout, no limit"},
      {BASE + 4, 0,  0, 0, TRUE, FALSE, TRUE, 0,
       "total: no timeout set, no limit"},
      {BASE + 4, 0,  10000, 0, FALSE, FALSE, TRUE, 6000,
       "total: 6 seconds should be left, not connecting"},

      /* CONNECT_ONLY: overall timeout applies while connecting ... */
      {BASE + 4, 0,  10000, 0, TRUE, TRUE, TRUE, 6000,
       "total connect_only: 6 seconds should be left while connecting"},
      {BASE + 12, 0, 10000, 0, TRUE, TRUE, TRUE, -2000,
       "total connect_only: -2000, overdue 2 seconds"},
      {BASE + 4, 0,  10000, 8000, TRUE, TRUE, FALSE, 4000,
       "connect_only: 4 seconds should be left while connecting"},
      {BASE + 12, 0, 10000, 8000, TRUE, TRUE, FALSE, -4000,
       "connect_only: -4000, overdue 4 seconds"},
      /* ... but not once the connect is done */
      {BASE + 12, 0, 10000, 0, FALSE, TRUE, TRUE, 0,
       "total connect_only: no limit when not connecting"},
      {BASE + 12, 0, 10000, 8000, FALSE, TRUE, FALSE, 0,
       "connect_only: no limit when not connecting"},
    };

    for(i = 0; i < CURL_ARRAYSIZE(run2); i++) {
      timediff_t timeout;
      NOW(run2[i].now_s, run2[i].now_us);
      TIMEOUTS(run2[i].timeout_ms, run2[i].connecttimeout_ms);
      easy->set.connect_only = run2[i].connect_only;
      easy->progress.now = now;
      easy->mstate = run2[i].connecting ? MSTATE_INIT : MSTATE_DO;
      timeout = run2[i].total ? Curl_timeleft_total_now_ms(easy, &now) :
                timeleft_now_ms(easy, &now);
      if(timeout != run2[i].result)
        fail(run2[i].comment);
    }
    easy->set.connect_only = FALSE;
  }

  UNITTEST_END(t1303_stop(easy))
}
