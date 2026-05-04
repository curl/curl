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

#include "parsedate.h"

static CURLcode test_unit3302(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  time_t t;
  int rc;

  /* valid RFC 7231 date (the example from the HTTP spec) */
  t = 0;
  rc = Curl_getdate_capped("Tue, 15 Nov 1994 12:45:26 GMT", &t);
  fail_unless(rc == 0, "valid date should return 0");
  fail_unless(t == 784903526, "RFC 7231 date should parse to 784903526");

  /* two-digit year: 94 -> 1994, same date */
  t = 0;
  rc = Curl_getdate_capped("Tue, 15 Nov 94 12:45:26 GMT", &t);
  fail_unless(rc == 0, "two-digit year date should return 0");
  fail_unless(t == 784903526, "two-digit year should parse to same timestamp");

  /* valid ANSI C asctime() format */
  t = 0;
  rc = Curl_getdate_capped("Tue Nov 15 12:45:26 1994", &t);
  fail_unless(rc == 0, "asctime date should return 0");
  fail_unless(t == 784903526, "asctime date should parse to same timestamp");

  /* Unix epoch */
  t = 1;
  rc = Curl_getdate_capped("Thu, 01 Jan 1970 00:00:00 GMT", &t);
  fail_unless(rc == 0, "epoch date should return 0");
  fail_unless(t == 0, "epoch date should parse to 0");

  /* malformed date - should fail */
  t = 99;
  rc = Curl_getdate_capped("not a date at all", &t);
  fail_unless(rc != 0, "malformed date should return non-zero");

  /* empty string - should fail */
  t = 99;
  rc = Curl_getdate_capped("", &t);
  fail_unless(rc != 0, "empty string should return non-zero");

  /* date without time defaults to 00:00:00 */
  t = 0;
  rc = Curl_getdate_capped("Tue, 15 Nov 1994", &t);
  fail_unless(rc == 0, "date without time should return 0");
  fail_unless(t == 784857600, "date without time should default to 00:00:00");

  UNITTEST_END_SIMPLE
}
