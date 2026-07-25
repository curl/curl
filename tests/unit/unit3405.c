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

/* curl_getdate is a public API declared in curl/curl.h, already pulled in
   via unitcheck.h -> curl_setup.h -> curl.h */

static CURLcode test_unit3405(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifndef CURL_DISABLE_PARSEDATE

  time_t t;

  /* ==================================================================
   * RFC 822 / RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
   * Expected epoch: 784111777
   * ================================================================== */
  t = curl_getdate("Sun, 06 Nov 1994 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)784111777,
              "RFC 1123 date must parse to epoch 784111777");

  /* ==================================================================
   * RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT"
   * ================================================================== */
  t = curl_getdate("Sunday, 06-Nov-94 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)784111777,
              "RFC 850 date must parse to epoch 784111777");

  /* ==================================================================
   * ANSI C asctime() format: "Sun Nov  6 08:49:37 1994"
   * ================================================================== */
  t = curl_getdate("Sun Nov  6 08:49:37 1994", NULL);
  fail_unless(t == (time_t)784111777,
              "asctime() format must parse to epoch 784111777");

  /* ==================================================================
   * Compact numerical: "19941106 08:49:37 GMT"
   * ================================================================== */
  t = curl_getdate("19941106 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)784111777,
              "compact YYYYMMDD format must parse to epoch 784111777");

  /* ==================================================================
   * Date without time (time defaults to 00:00:00)
   * "06 Nov 1994" -> 784080000
   * ================================================================== */
  t = curl_getdate("06 Nov 1994", NULL);
  fail_unless(t == (time_t)784080000,
              "date without time must default to 00:00:00 UTC");

  /* ==================================================================
   * Epoch itself: "01 Jan 1970 00:00:00 GMT" -> 0
   * ================================================================== */
  t = curl_getdate("01 Jan 1970 00:00:00 GMT", NULL);
  fail_unless(t == (time_t)0,
              "Unix epoch date must parse to 0");

  /* ==================================================================
   * RFC 822 with numeric timezone offset "+0200"
   * "12 Sep 2004 15:05:58 +0200" -> UTC 13:05:58 on 2004-09-12
   * Expected epoch: 1094994358
   * ================================================================== */
  t = curl_getdate("12 Sep 2004 15:05:58 +0200", NULL);
  fail_unless(t == (time_t)1094994358,
              "date with +0200 offset must be adjusted to UTC");

  /* ==================================================================
   * RFC 822 with negative timezone offset "-0700"
   * "12 Sep 2004 15:05:58 -0700" -> UTC 22:05:58 on 2004-09-12
   * Expected epoch: 1095026758
   * ================================================================== */
  t = curl_getdate("12 Sep 2004 15:05:58 -0700", NULL);
  fail_unless(t == (time_t)1095026758,
              "date with -0700 offset must be adjusted to UTC");

  /* ==================================================================
   * Named timezone: CET = UTC+1 (offset -60 min in curl's tz table)
   * "06 Nov 1994 08:49:37 CET" -> subtract 3600s from GMT equivalent
   * Expected epoch: 784111777 - 3600 = 784108177
   * ================================================================== */
  t = curl_getdate("06 Nov 1994 08:49:37 CET", NULL);
  fail_unless(t == (time_t)784108177,
              "CET timezone must subtract 3600s from the UTC value");

  /* ==================================================================
   * Two-digit year >= 70 -> 19xx
   * "06-Nov-94 08:49:37 GMT" -> year 1994
   * ================================================================== */
  t = curl_getdate("06-Nov-94 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)784111777,
              "two-digit year 94 must be treated as 1994");

  /* ==================================================================
   * Two-digit year < 70 -> 20xx
   * "06 Nov 04 08:49:37 GMT" -> year 2004
   * Expected epoch: 1099730977
   * ================================================================== */
  t = curl_getdate("06 Nov 04 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)1099730977,
              "two-digit year 04 must be treated as 2004");

  /* ==================================================================
   * Earliest valid year boundary: year 1583 (Gregorian calendar start).
   * Anything before 1583 must fail.
   * ================================================================== */
  t = curl_getdate("01 Jan 1582 00:00:00 GMT", NULL);
  fail_unless(t == (time_t)-1,
              "year 1582 is before Gregorian calendar, must return -1");

  /* ==================================================================
   * Invalid / garbage input must return -1
   * ================================================================== */
  t = curl_getdate("not a date at all", NULL);
  fail_unless(t == (time_t)-1,
              "garbage input must return -1");

  t = curl_getdate("", NULL);
  fail_unless(t == (time_t)-1,
              "empty string must return -1");

  t = curl_getdate("32 Nov 1994 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)-1,
              "day=32 is illegal, must return -1");

  t = curl_getdate("06 Nov 1994 25:00:00 GMT", NULL);
  fail_unless(t == (time_t)-1,
              "hour=25 is illegal, must return -1");

  t = curl_getdate("06 Foo 1994 08:49:37 GMT", NULL);
  fail_unless(t == (time_t)-1,
              "unknown month name must return -1");

#endif /* CURL_DISABLE_PARSEDATE */

  UNITTEST_END_SIMPLE
}
