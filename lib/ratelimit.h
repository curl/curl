#ifndef HEADER_Curl_rlimit_H
#define HEADER_Curl_rlimit_H
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

#include "curlx/timeval.h"

/* This is a rate limiter that provides "tokens" to be consumed
 * per second with a "burst" rate limitation. Example:
 * A rate limit of 1 megabyte per second with a burst rate of 1.5MB.
 * - initially 1 million tokens are available.
 * - these are drained in the first second.
 * - checking available tokens before the 2nd second will return 0.
 * - at/after the 2nd second, 1 million tokens are available again.
 * - nothing happens for a second, the 1 million tokens would grow
 *   to 2 million, however the burst limit caps those at 1.5 million.
 * Thus:
 * - setting "burst" to CURL_OFF_T_MAX would average tokens over the
 *   complete lifetime. E.g. for a download, at the *end* of it, the
 *   average rate from start to finish would be the rate limit.
 * - setting "burst" to the same value as "rate" would make a
 *   download always try to stay *at/below* the rate and slow times will
 *   not generate extra tokens.
 * A rate limit can be blocked, causing the available tokens to become
 * always 0 until unblocked. After unblocking, the rate limiting starts
 * again with no history of the past.
 * Finally, a rate limiter with rate 0 will always have CURL_OFF_T_MAX
 * tokens available, unless blocked.
 */

struct Curl_rlimit {
  curl_off_t rate_per_step; /* rate tokens are generated per step us */
  curl_off_t burst_per_step; /* burst rate of tokens per step us */
  timediff_t step_us;     /* microseconds between token increases */
  curl_off_t tokens;      /* tokens available in the next second */
  timediff_t spare_us;    /* microseconds unaffecting tokens */
  struct curltime ts;     /* time of the last update */
  BIT(blocked);           /* blocking sets available tokens to 0 */
};

void Curl_rlimit_init(struct Curl_rlimit *r,
                      curl_off_t rate_per_s,
                      curl_off_t burst_per_s,
                      struct curltime *pts);

/* Start ratelimiting with the given timestamp. Resets available tokens. */
void Curl_rlimit_start(struct Curl_rlimit *r, struct curltime *pts);

/* How many milliseconds to wait until token are available again. */
timediff_t Curl_rlimit_wait_ms(struct Curl_rlimit *r,
                               struct curltime *pts);

/* Return if rate limiting of tokens is active */
bool Curl_rlimit_active(struct Curl_rlimit *r);
bool Curl_rlimit_is_blocked(struct Curl_rlimit *r);

/* Return how many tokens are available to spend, may be negative */
curl_off_t Curl_rlimit_avail(struct Curl_rlimit *r,
                             struct curltime *pts);

/* Drain tokens from the ratelimit, return how many are now available. */
void Curl_rlimit_drain(struct Curl_rlimit *r,
                       size_t tokens,
                       struct curltime *pts);

/* Block/unblock ratelimiting. A blocked ratelimit has 0 tokens available. */
void Curl_rlimit_block(struct Curl_rlimit *r,
                       bool activate,
                       struct curltime *pts);

#endif /* HEADER_Curl_rlimit_H */
