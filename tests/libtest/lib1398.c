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

#ifdef CURL_HAVE_DIAG
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#endif

static CURLcode test_lib1398(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  int rc;
  char buf[3] = { 'b', 'u', 'g' };
  static const char str[] = "bug";
  int width = 3;
  char output[130];

/* #define curl_msnprintf snprintf */

  /* negative precision is treated as if omitted */
  rc = curl_msnprintf(output, sizeof(output), "%.*s", -1, str);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "bug"), "wrong output");

  rc = curl_msnprintf(output, sizeof(output), "%.*s", -1, "0123456789");
  fail_unless(rc == 10, "return code should be 10");
  fail_unless(!strcmp(output, "0123456789"), "wrong output");

  rc = curl_msnprintf(output, sizeof(output), "%.*s", 0, "0123456789");
  fail_unless(rc == 0, "return code should be 0");
  fail_unless(!strcmp(output, ""), "wrong output");

  rc = curl_msnprintf(output, sizeof(output), "%.*s", -2, str);
  fail_unless(rc == 3, "return code should be 3");
  fail_unless(!strcmp(output, "bug"), "wrong output");

  rc = curl_msnprintf(output, sizeof(output), "%.*d", -3, 10000);
  fail_unless(rc == 5, "return code should be 5");
  fail_unless(!strcmp(output, "10000"), "wrong output");

  rc = curl_msnprintf(output, sizeof(output), "%.*d", 0, 1234567);
  fail_unless(rc == 7, "return code should be 0");
  fail_unless(!strcmp(output, "1234567"), "wrong output");

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
                      "%s%s%s%s%s%s%s%s%s",  /* 129 */

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
                      "m", "", "", "", "", "", "", "", ""      /* 129 */
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
                      "%s%s%s%s%s%s%s%s",    /* 128 */

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
                      "m", "", "", "", "", "", "", ""          /* 128 */
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
                      "%%%%%%%%%%%%%%%%%%"                       /* 129 */
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
                      "%%%%%%%%%%%%%%%%"                         /* 128 */
  );
  fail_unless(rc == 128, "return code should be 128");

  /* Literal text plus unadorned %s, %c, %d, %u and %% goes through the
     fast path in mprintf.c; adding a width does not. Formatting the same
     arguments both ways must produce the same bytes.

     A width of 1 changes no output here: out_string() subtracts the string
     length from the width before padding and the %c and integer paths do
     likewise, so a non-empty conversion leaves nothing to pad. */
  {
    char fast[600];
    char gen[600];
    /* 512 bytes, one byte longer than the staging buffer. Built here rather
       than written as a literal: C90 requires support for only 509
       characters in a string literal, and that limit applies after
       concatenation. */
    char lstr[513];
    int rcf, rcg;

    memset(lstr, 'x', sizeof(lstr) - 1);
    lstr[sizeof(lstr) - 1] = '\0';

    /* a request line */
    rcf = curl_msnprintf(fast, sizeof(fast), "%s %s HTTP/1.1\r\n",
                         "POST", "/path");
    rcg = curl_msnprintf(gen, sizeof(gen), "%1s %1s HTTP/1.1\r\n",
                         "POST", "/path");
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");
    fail_unless(!strcmp(fast, "POST /path HTTP/1.1\r\n"), "wrong output");

    /* %d, including the value whose negation overflows */
    rcf = curl_msnprintf(fast, sizeof(fast), "[%d][%d][%d]",
                         0, -1, INT_MIN);
    rcg = curl_msnprintf(gen, sizeof(gen), "[%1d][%1d][%1d]",
                         0, -1, INT_MIN);
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");

    /* %u at the top of its range */
    rcf = curl_msnprintf(fast, sizeof(fast), "[%u][%u]", 0U, UINT_MAX);
    rcg = curl_msnprintf(gen, sizeof(gen), "[%1u][%1u]", 0U, UINT_MAX);
    fail_unless(rcf == rcg, "fast and general output differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");

    /* %c and a literal percent next to conversions */
    rcf = curl_msnprintf(fast, sizeof(fast), "%c%%%c 100%%", 'o', 'k');
    rcg = curl_msnprintf(gen, sizeof(gen), "%1c%%%1c 100%%", 'o', 'k');
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");
    fail_unless(!strcmp(fast, "o%k 100%"), "wrong output");

    /* a NULL %s renders as (nil) on both paths */
    rcf = curl_msnprintf(fast, sizeof(fast), "[%s]", (char *)NULL);
    rcg = curl_msnprintf(gen, sizeof(gen), "[%1s]", (char *)NULL);
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");
    fail_unless(!strcmp(fast, "[(nil)]"), "wrong output");

    /* an empty %s, where a width would legitimately differ */
    rcf = curl_msnprintf(fast, sizeof(fast), "[%s]", "");
    fail_unless(rcf == 2, "return code should be 2");
    fail_unless(!strcmp(fast, "[]"), "wrong output");

    /* long enough to flush the staging buffer mid-format */
    rcf = curl_msnprintf(fast, sizeof(fast), "%s", lstr);
    rcg = curl_msnprintf(gen, sizeof(gen), "%1s", lstr);
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");
    fail_unless(rcf == (int)(sizeof(lstr) - 1), "wrong length");

    /* off_t / size_t conversions the fast path now accepts: %lld %ld %llu
       %lu %zu, at the boundaries where a wrong va_arg width or sign shows. A
       '1' width forces the general path. %zd and %ld share the signed path
       with %lld, and %zu shares the z width, so the two together cover %zd. */
    {
      long long ll = -9223372036854775807LL - 1; /* INT64_MIN */
      unsigned long long ull = 18446744073709551615ULL; /* UINT64_MAX */
      long lv = -1234567L;
      unsigned long ulv = 4000000000UL;
      size_t zv = (size_t)-1; /* SIZE_MAX */

      rcf = curl_msnprintf(fast, sizeof(fast), "[%lld][%llu]", ll, ull);
      rcg = curl_msnprintf(gen, sizeof(gen), "[%1lld][%1llu]", ll, ull);
      fail_unless(rcf == rcg, "fast and general lengths differ");
      fail_unless(!strcmp(fast, gen), "fast and general output differ");

      rcf = curl_msnprintf(fast, sizeof(fast), "[%ld][%lu]", lv, ulv);
      rcg = curl_msnprintf(gen, sizeof(gen), "[%1ld][%1lu]", lv, ulv);
      fail_unless(rcf == rcg, "fast and general lengths differ");
      fail_unless(!strcmp(fast, gen), "fast and general output differ");

      rcf = curl_msnprintf(fast, sizeof(fast), "[%zu]", zv);
      rcg = curl_msnprintf(gen, sizeof(gen), "[%1zu]", zv);
      fail_unless(rcf == rcg, "fast and general lengths differ");
      fail_unless(!strcmp(fast, gen), "fast and general output differ");

      /* the curl_off_t form that lib/http.c emits on every request body */
      rcf = curl_msnprintf(fast, sizeof(fast),
                           "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n",
                           (curl_off_t)5368709120LL);
      fail_unless(rcf == 28, "wrong length");
      fail_unless(!strcmp(fast, "Content-Length: 5368709120\r\n"),
                  "wrong output");
    }

    /* truncation into a short buffer */
    rcf = curl_msnprintf(fast, 8, "%s%d", "abc", 4567);
    rcg = curl_msnprintf(gen, 8, "%1s%1d", "abc", 4567);
    fail_unless(rcf == rcg, "fast and general lengths differ");
    fail_unless(!strcmp(fast, gen), "fast and general output differ");
  }

  UNITTEST_END_SIMPLE
}

#ifdef CURL_HAVE_DIAG
#pragma GCC diagnostic pop
#endif
