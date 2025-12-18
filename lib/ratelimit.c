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


#define CURL_US_PER_SEC       1000000
#define CURL_RLIMIT_MIN_CHUNK (16 * 1024)
#define CURL_RLIMIT_MAX_STEPS 2   /* 500ms interval */

void Curl_rlimit_init(struct Curl_rlimit *r,
                      curl_off_t rate_per_s,
                      curl_off_t burst_per_s,
                      const struct curltime *pts)
{
  curl_off_t rate_steps;

  DEBUGASSERT(rate_per_s >= 0);
  DEBUGASSERT(burst_per_s >= rate_per_s || !burst_per_s);
  DEBUGASSERT(pts);
  r->step_us = CURL_US_PER_SEC;
  r->rate_per_step = rate_per_s;
  r->burst_per_step = burst_per_s;
  /* On rates that are multiples of CURL_RLIMIT_MIN_CHUNK, we reduce
   * the interval `step_us` from 1 second to smaller steps with at
   * most CURL_RLIMIT_MAX_STEPS.
   * Smaller means more CPU, but also more precision. */
  rate_steps = rate_per_s / CURL_RLIMIT_MIN_CHUNK;
  rate_steps = CURLMIN(rate_steps, CURL_RLIMIT_MAX_STEPS);
  if(rate_steps >= 2) {
    r->step_us /= rate_steps;
    r->rate_per_step /= rate_steps;
    r->burst_per_step /= rate_steps;
  }
  r->tokens = r->rate_per_step;
  r->spare_us = 0;
  r->ts = *pts;
  r->blocked = FALSE;
}

void Curl_rlimit_start(struct Curl_rlimit *r, const struct curltime *pts)
{
  r->tokens = r->rate_per_step;
  r->spare_us = 0;
  r->ts = *pts;
}

bool Curl_rlimit_active(struct Curl_rlimit *r)
{
  return (r->rate_per_step > 0) || r->blocked;
}

bool Curl_rlimit_is_blocked(struct Curl_rlimit *r)
{
  return r->blocked;
}

static void ratelimit_update(struct Curl_rlimit *r,
                             const struct curltime *pts)
{
  timediff_t elapsed_us, elapsed_steps;
  curl_off_t token_gain;

  DEBUGASSERT(r->rate_per_step);
  if((r->ts.tv_sec == pts->tv_sec) && (r->ts.tv_usec == pts->tv_usec))
    return;

  elapsed_us = curlx_ptimediff_us(pts, &r->ts);
  if(elapsed_us < 0) { /* not going back in time */
    DEBUGASSERT(0);
    return;
  }

  elapsed_us += r->spare_us;
  if(elapsed_us < r->step_us)
    return;

  /* we do the update */
  r->ts = *pts;
  elapsed_steps = elapsed_us / r->step_us;
  r->spare_us = elapsed_us % r->step_us;

  /* How many tokens did we gain since the last update? */
  if(r->rate_per_step > (CURL_OFF_T_MAX / elapsed_steps))
    token_gain = CURL_OFF_T_MAX;
  else {
    token_gain = r->rate_per_step * elapsed_steps;
  }

  /* Limit the token again by the burst rate per second (if set), so we
   * do not suddenly have a huge number of tokens after inactivity. */
  r->tokens += token_gain;
  if(r->burst_per_step && (r->tokens > r->burst_per_step)) {
    r->tokens = r->burst_per_step;
  }
}

curl_off_t Curl_rlimit_avail(struct Curl_rlimit *r,
                             const struct curltime *pts)
{
  if(r->blocked)
    return 0;
  else if(r->rate_per_step) {
    ratelimit_update(r, pts);
    return r->tokens;
  }
  else
    return CURL_OFF_T_MAX;
}

void Curl_rlimit_drain(struct Curl_rlimit *r,
                       size_t tokens,
                       const struct curltime *pts)
{
  if(r->blocked || !r->rate_per_step)
    return;

  ratelimit_update(r, pts);
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
                               const struct curltime *pts)
{
  timediff_t wait_us, elapsed_us;

  if(r->blocked || !r->rate_per_step)
    return 0;
  ratelimit_update(r, pts);
  if(r->tokens > 0)
    return 0;

  /* How much time will it take tokens to become positive again?
   * Deduct `spare_us` and check against already elapsed time */
  wait_us = (1 + (-r->tokens / r->rate_per_step)) * r->step_us;
  wait_us -= r->spare_us;

  elapsed_us = curlx_ptimediff_us(pts, &r->ts);
  if(elapsed_us >= wait_us)
    return 0;
  wait_us -= elapsed_us;
  return (wait_us + 999) / 1000; /* in milliseconds */
}

void Curl_rlimit_block(struct Curl_rlimit *r,
                       bool activate,
                       const struct curltime *pts)
{
  if(!activate == !r->blocked)
    return;

  r->ts = *pts;
  r->blocked = activate;
  if(!r->blocked) {
    /* Start rate limiting fresh. The amount of time this was blocked
     * does not generate extra tokens. */
    Curl_rlimit_start(r, pts);
  }
  else {
    r->tokens = 0;
  }
}
