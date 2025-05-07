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
#include "curlcheck.h"

#include "urldata.h"
#include "uint-spbset.h"
#include "curl_trc.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static unsigned int s1_3213[] = {  /* spread numbers, some at slot edges */
  0, 1, 4, 17, 63, 64, 65, 66,
  90, 99,
};
static unsigned int s2_3213[] = { /* set with all bits in slot1 set */
  64, 65, 66, 67, 68, 69, 70, 71,
  72, 73, 74, 75, 76, 77, 78, 79,
  80, 81, 82, 83, 84, 85, 86, 87,
  88, 89, 90, 91, 92, 93, 94, 95,
  96, 97, 98, 99, 100, 101, 102, 103,
  104, 105, 106, 107, 108, 109, 110, 111,
  112, 113, 114, 115, 116, 117, 118, 119,
  120, 121, 122, 123, 124, 125, 126, 127,
};
static unsigned int s3_3213[] = {  /* very spread numbers */
  2232, 5167, 8204, 8526, 8641, 10056, 10140, 10611,
  10998, 11626, 13735, 15539, 17947, 24295, 27833, 30318,
};

static void check_spbset(const char *name, unsigned int *s, size_t slen)
{
  struct uint_spbset bset;
  size_t i, j;
  unsigned int n, c;

  curl_mfprintf(stderr, "test %s, %zu numbers\n", name, slen);

  Curl_uint_spbset_init(&bset);

  Curl_uint_spbset_clear(&bset);
  c = Curl_uint_spbset_count(&bset);
  fail_unless(c == 0, "set count is not 0");

  for(i = 0; i < slen; ++i) { /* add all */
    fail_unless(Curl_uint_spbset_add(&bset, s[i]), "failed to add");
    for(j = i + 1; j < slen; ++j)
      fail_unless(!Curl_uint_spbset_contains(&bset, s[j]),
                  "unexpectedly found");
  }

  for(i = 0; i < slen; ++i) { /* all present */
    fail_unless(Curl_uint_spbset_contains(&bset, s[i]),
                "failed presence check");
  }

  /* iterator over all numbers */
  fail_unless(Curl_uint_spbset_first(&bset, &n), "first failed");
  fail_unless(n == s[0], "first not correct number");
  for(i = 1; i < slen; ++i) {
    fail_unless(Curl_uint_spbset_next(&bset, n, &n), "next failed");
    if(n != s[i]) {
      curl_mfprintf(stderr, "expected next to be %u, not %u\n", s[i], n);
      fail_unless(n == s[i], "next not correct number");
    }
  }

  for(i = 0; i < slen; i += 2) { /* remove every 2nd */
    Curl_uint_spbset_remove(&bset, s[i]);
    fail_unless(!Curl_uint_spbset_contains(&bset, s[i]), "unexpectedly found");
  }
  for(i = 1; i < slen; i += 2) { /* others still there */
    fail_unless(Curl_uint_spbset_contains(&bset, s[i]), "unexpectedly gone");
  }
  /* The count is half */
  c = Curl_uint_spbset_count(&bset);
  fail_unless(c == slen/2, "set count is wrong");

  Curl_uint_spbset_clear(&bset);
  c = Curl_uint_spbset_count(&bset);
  fail_unless(c == 0, "set count is not 0");
  for(i = 0; i < slen; i++) { /* none present any longer */
    fail_unless(!Curl_uint_spbset_contains(&bset, s[i]), "unexpectedly there");
  }

  for(i = 0; i < slen; ++i) { /* add all again */
    fail_unless(Curl_uint_spbset_add(&bset, s[i]), "failed to add");
  }

  Curl_uint_spbset_destroy(&bset);
}

static void unit_stop(void)
{
}


UNITTEST_START

  check_spbset("s1", s1_3213, CURL_ARRAYSIZE(s1_3213));
  check_spbset("s2", s2_3213, CURL_ARRAYSIZE(s2_3213));
  check_spbset("s3", s3_3213, CURL_ARRAYSIZE(s3_3213));

UNITTEST_STOP
