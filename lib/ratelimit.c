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

#include "curl_setup.h"

#include "curlx/timeval.h"
#include "ratelimit.h"


#define CURL_US_PER_SEC      1000000

void Curl_rlimit_init(struct Curl_rlimit *r,
                      curl_off_t rate_per_s,
                      curl_off_t burst_per_s,
                      struct curltime ts)
{
  DEBUGASSERT(rate_per_s >= 0);
  DEBUGASSERT(burst_per_s >= rate_per_s || !burst_per_s);
  r->rate_per_s = rate_per_s;
  r->burst_per_s = burst_per_s;
  r->tokens = rate_per_s;
  r->spare_us = 0;
  r->ts = ts;
  r->blocked = FALSE;
}

void Curl_rlimit_start(struct Curl_rlimit *r, struct curltime ts)
{
  r->tokens = r->rate_per_s;
  r->spare_us = 0;
  r->ts = ts;
}

bool Curl_rlimit_active(struct Curl_rlimit *r)
{
  return (r->rate_per_s > 0) || r->blocked;
}

bool Curl_rlimit_is_blocked(struct Curl_rlimit *r)
{
  return r->blocked;
}

static void ratelimit_update(struct Curl_rlimit *r,
                             struct curltime ts)
{
  timediff_t elapsed_us, elapsed_s;
  curl_off_t token_gain;

  DEBUGASSERT(r->rate_per_s);
  if((r->ts.tv_sec == ts.tv_sec) && (r->ts.tv_usec == ts.tv_usec))
    return;

  elapsed_us = curlx_timediff_us(ts, r->ts);
  if(elapsed_us < 0) { /* not going back in time */
    curl_mfprintf(stderr, "rlimit: neg elapsed time %" FMT_TIMEDIFF_T "us\n",
                  elapsed_us);
    DEBUGASSERT(0);
    return;
  }

  elapsed_us += r->spare_us;
  if(elapsed_us < CURL_US_PER_SEC)
    return;

  /* we do the update */
  r->ts = ts;
  elapsed_s = elapsed_us / CURL_US_PER_SEC;
  r->spare_us = elapsed_us % CURL_US_PER_SEC;

  /* How many tokens did we gain since the last update? */
  if(r->rate_per_s > (CURL_OFF_T_MAX / elapsed_s))
    token_gain = CURL_OFF_T_MAX;
  else {
    token_gain = r->rate_per_s * elapsed_s;
  }

  /* Limit the token again by the burst rate per second (if set), so we
   * do not suddenly have a huge number of tokens after inactivity. */
  r->tokens += token_gain;
  if(r->burst_per_s && (r->tokens > r->burst_per_s)) {
    r->tokens = r->burst_per_s;
  }
}

curl_off_t Curl_rlimit_avail(struct Curl_rlimit *r,
                             struct curltime ts)
{
  if(r->blocked)
    return 0;
  else if(r->rate_per_s) {
    ratelimit_update(r, ts);
    return r->tokens;
  }
  else
    return CURL_OFF_T_MAX;
}

void Curl_rlimit_drain(struct Curl_rlimit *r,
                       size_t tokens,
                       struct curltime ts)
{
  if(r->blocked || !r->rate_per_s)
    return;

  ratelimit_update(r, ts);
#if SIZEOF_CURL_OFF_T <= SIZEOF_SIZE_T
  if(tokens > CURL_OFF_T_MAX) {
    r->tokens = CURL_OFF_T_MIN;
    return;
  }
  else
#endif
  {
    curl_off_t val = (curl_off_t)tokens;
    if((CURL_OFF_T_MIN + val) < r->tokens)
      r->tokens -= val;
    else
      r->tokens = CURL_OFF_T_MIN;
  }
}

timediff_t Curl_rlimit_wait_ms(struct Curl_rlimit *r,
                               struct curltime ts)
{
  timediff_t wait_us, elapsed_us;

  if(r->blocked || !r->rate_per_s)
    return 0;
  ratelimit_update(r, ts);
  if(r->tokens > 0)
    return 0;

  /* How many seconds will it take tokens to become positive again?
   * Deduct `spare_us` and check against already elapsed time */
  wait_us = (1 + (-r->tokens / r->rate_per_s)) * CURL_US_PER_SEC;
  wait_us -= r->spare_us;

  elapsed_us = curlx_timediff_us(ts, r->ts);
  if(elapsed_us >= wait_us)
    return 0;
  wait_us -= elapsed_us;
  return (wait_us + 999) / 1000; /* in milliseconds */
}

void Curl_rlimit_block(struct Curl_rlimit *r,
                       bool activate,
                       struct curltime ts)
{
  if(!activate == !r->blocked)
    return;

  r->ts = ts;
  r->blocked = activate;
  if(!r->blocked) {
    /* Start rate limiting fresh. The amount of time this was blocked
     * does not generate extra tokens. */
    Curl_rlimit_start(r, ts);
  }
  else {
    r->tokens = 0;
  }
}
