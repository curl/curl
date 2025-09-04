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

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#endif

static CURLcode test_unit1398(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  int rc;
  char buf[3] = {'b', 'u', 'g'};
  static const char *str = "bug";
  int width = 3;
  char output[130];

  /*#define curl_msnprintf snprintf */

  /* without a trailing zero */
  rc = curl_msnprintf(output, 4, "%.*s", width, buf);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "bug"), "wrong output");

  /* with a trailing zero */
  rc = curl_msnprintf(output, 4, "%.*s", width, str);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "bug"), "wrong output");

  width = 2;
  /* one byte less */
  rc = curl_msnprintf(output, 4, "%.*s", width, buf);
  fail_unless(rc == 2, "return code should be 2");
  fail_unless(!strcmp(output, "bu"), "wrong output");

  /* string with larger precision */
  rc = curl_msnprintf(output, 8, "%.8s", str);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "bug"), "wrong output");

  /* longer string with precision */
  rc = curl_msnprintf(output, 8, "%.3s", "0123456789");
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "012"), "wrong output");

  /* negative width */
  rc = curl_msnprintf(output, 8, "%-8s", str);
  fail_unless(rc == 7, "return code should be 7");
  fail_unless(!strcmp(output, "bug    "), "wrong output");

  /* larger width that string length */
  rc = curl_msnprintf(output, 8, "%8s", str);
  fail_unless(rc == 7, "return code should be 7");
  fail_unless(!strcmp(output, "     bu"), "wrong output");

  /* output a number in a limited output */
  rc = curl_msnprintf(output, 4, "%d", 10240);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "102"), "wrong output");

  /* padded strings */
  rc = curl_msnprintf(output, 16, "%8s%8s", str, str);
  fail_unless(rc == 15, "return code should be 15");
  fail_unless(!strcmp(output, "     bug     bu"), "wrong output");

  /* padded numbers */
  rc = curl_msnprintf(output, 16, "%8d%8d", 1234, 5678);
  fail_unless(rc == 15, "return code should be 15");
  fail_unless(!strcmp(output, "    1234    567"), "wrong output");

#if defined(__clang__) && \
  (__clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 1))
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-non-iso"
#endif
  /* double precision */
  rc = curl_msnprintf(output, 24, "%2$.*1$.99d", 3, 5678);
  fail_unless(rc == 0, "return code should be 0");
#if defined(__clang__) && \
  (__clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 1))
#pragma clang diagnostic pop
#endif

  /* 129 input % flags */
  rc = curl_msnprintf(output, 130,
                      "%s%s%s%s%s%s%s%s%s%s" /* 10 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 20 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 30 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 40 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 50 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 60 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 70 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 80 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 90 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 100 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 110 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 120 */
                      "%s%s%s%s%s%s%s%s%s", /* 129 */

                      "a", "", "", "", "", "", "", "", "", "", /* 10 */
                      "b", "", "", "", "", "", "", "", "", "", /* 20 */
                      "c", "", "", "", "", "", "", "", "", "", /* 30 */
                      "d", "", "", "", "", "", "", "", "", "", /* 40 */
                      "e", "", "", "", "", "", "", "", "", "", /* 50 */
                      "f", "", "", "", "", "", "", "", "", "", /* 60 */
                      "g", "", "", "", "", "", "", "", "", "", /* 70 */
                      "h", "", "", "", "", "", "", "", "", "", /* 80 */
                      "i", "", "", "", "", "", "", "", "", "", /* 90 */
                      "j", "", "", "", "", "", "", "", "", "", /* 100 */
                      "k", "", "", "", "", "", "", "", "", "", /* 110 */
                      "l", "", "", "", "", "", "", "", "", "", /* 120 */
                      "m", "", "", "", "", "", "", "", ""  /* 129 */
    );
  fail_unless(rc == 0, "return code should be 0");

  /* 128 input % flags */
  rc = curl_msnprintf(output, 130,
                      "%s%s%s%s%s%s%s%s%s%s" /* 10 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 20 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 30 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 40 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 50 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 60 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 70 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 80 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 90 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 100 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 110 */
                      "%s%s%s%s%s%s%s%s%s%s" /* 120 */
                      "%s%s%s%s%s%s%s%s", /* 128 */

                      "a", "", "", "", "", "", "", "", "", "", /* 10 */
                      "b", "", "", "", "", "", "", "", "", "", /* 20 */
                      "c", "", "", "", "", "", "", "", "", "", /* 30 */
                      "d", "", "", "", "", "", "", "", "", "", /* 40 */
                      "e", "", "", "", "", "", "", "", "", "", /* 50 */
                      "f", "", "", "", "", "", "", "", "", "", /* 60 */
                      "g", "", "", "", "", "", "", "", "", "", /* 70 */
                      "h", "", "", "", "", "", "", "", "", "", /* 80 */
                      "i", "", "", "", "", "", "", "", "", "", /* 90 */
                      "j", "", "", "", "", "", "", "", "", "", /* 100 */
                      "k", "", "", "", "", "", "", "", "", "", /* 110 */
                      "l", "", "", "", "", "", "", "", "", "", /* 120 */
                      "m", "", "", "", "", "", "", ""  /* 128 */
    );
  fail_unless(rc == 13, "return code should be 13");

  /* 129 output segments */
  rc = curl_msnprintf(output, 130,
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 20 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 40 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 60 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 80 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 100 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 120 */
                      "%%%%%%%%%%%%%%%%%%" /* 129 */
    );
  fail_unless(rc == 0, "return code should be 0");

  /* 128 output segments */
  rc = curl_msnprintf(output, 129,
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 20 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 40 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 60 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 80 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 100 */
                      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" /* 120 */
                      "%%%%%%%%%%%%%%%%" /* 128 */
    );
  fail_unless(rc == 128, "return code should be 128");

  UNITTEST_END_SIMPLE
}

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
