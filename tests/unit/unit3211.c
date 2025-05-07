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
#include "uint-bset.h"
#include "curl_trc.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static unsigned int s1[] = {  /* spread numbers, some at slot edges */
  0, 1, 4, 17, 63, 64, 65, 66,
  90, 99,
};
static unsigned int s2[] = { /* set with all bits in slot1 set */
  64, 65, 66, 67, 68, 69, 70, 71,
  72, 73, 74, 75, 76, 77, 78, 79,
  80, 81, 82, 83, 84, 85, 86, 87,
  88, 89, 90, 91, 92, 93, 94, 95,
  96, 97, 98, 99, 100, 101, 102, 103,
  104, 105, 106, 107, 108, 109, 110, 111,
  112, 113, 114, 115, 116, 117, 118, 119,
  120, 121, 122, 123, 124, 125, 126, 127,
};

static void check_set(const char *name, unsigned int capacity,
                      unsigned int *s, size_t slen)
{
  struct uint_bset bset;
  size_t i, j;
  unsigned int n, c;

  curl_mfprintf(stderr, "test %s, capacity=%u, %zu numbers\n",
                name, capacity, slen);
  Curl_uint_bset_init(&bset);
  fail_unless(!Curl_uint_bset_resize(&bset, capacity), "bset resize failed");
  c = Curl_uint_bset_capacity(&bset);
  fail_unless(c == (((capacity + 63) / 64) * 64), "wrong capacity");

  Curl_uint_bset_clear(&bset);
  c = Curl_uint_bset_count(&bset);
  fail_unless(c == 0, "set count is not 0");

  for(i = 0; i < slen; ++i) { /* add all */
    fail_unless(Curl_uint_bset_add(&bset, s[i]), "failed to add");
    for(j = i + 1; j < slen; ++j)
      fail_unless(!Curl_uint_bset_contains(&bset, s[j]), "unexpectedly found");
  }

  for(i = 0; i < slen; ++i) { /* all present */
    fail_unless(Curl_uint_bset_contains(&bset, s[i]), "failed presence check");
  }

  /* iterator over all numbers */
  fail_unless(Curl_uint_bset_first(&bset, &n), "first failed");
  fail_unless(n == s[0], "first not correct number");
  for(i = 1; i < slen; ++i) {
    fail_unless(Curl_uint_bset_next(&bset, n, &n), "next failed");
    if(n != s[i]) {
      curl_mfprintf(stderr, "expected next to be %u, not %u\n", s[i], n);
      fail_unless(n == s[i], "next not correct number");
    }
  }

  /* Adding capacity number does not work (0 - capacity-1) */
  c = Curl_uint_bset_capacity(&bset);
  fail_unless(!Curl_uint_bset_add(&bset, c), "add out of range worked");
  /* The count it correct */
  c = Curl_uint_bset_count(&bset);
  fail_unless(c == slen, "set count is wrong");

  for(i = 0; i < slen; i += 2) { /* remove every 2nd */
    Curl_uint_bset_remove(&bset, s[i]);
    fail_unless(!Curl_uint_bset_contains(&bset, s[i]), "unexpectedly found");
  }
  for(i = 1; i < slen; i += 2) { /* others still there */
    fail_unless(Curl_uint_bset_contains(&bset, s[i]), "unexpectedly gone");
  }
  /* The count is half */
  c = Curl_uint_bset_count(&bset);
  fail_unless(c == slen/2, "set count is wrong");

  Curl_uint_bset_clear(&bset);
  c = Curl_uint_bset_count(&bset);
  fail_unless(c == 0, "set count is not 0");
  for(i = 0; i < slen; i++) { /* none present any longer */
    fail_unless(!Curl_uint_bset_contains(&bset, s[i]), "unexpectedly there");
  }

  for(i = 0; i < slen; ++i) { /* add all again */
    fail_unless(Curl_uint_bset_add(&bset, s[i]), "failed to add");
  }

  fail_unless(!Curl_uint_bset_resize(&bset, capacity * 2),
              "resize double failed");
  for(i = 0; i < slen; i++) { /* all still present after resize */
    fail_unless(Curl_uint_bset_contains(&bset, s[i]), "unexpectedly lost");
  }

  fail_unless(!Curl_uint_bset_resize(&bset, capacity), "resize back failed");
  for(i = 0; i < slen; i++)  /* all still present after resize back */
    fail_unless(Curl_uint_bset_contains(&bset, s[i]), "unexpectedly lost");

  fail_unless(!Curl_uint_bset_resize(&bset, capacity/2), "resize half failed");
  /* halfed the size, what numbers remain in set? */
  c = Curl_uint_bset_capacity(&bset);
  n = 0;
  for(i = 0; i < slen; ++i) {
    if(s[i] < c)
      ++n;
  }
  fail_unless(n == Curl_uint_bset_count(&bset), "set count(halfed) wrong");
  for(i = 0; i < n; i++)  /* still present after resize half */
    fail_unless(Curl_uint_bset_contains(&bset, s[i]), "unexpectedly lost");

  Curl_uint_bset_destroy(&bset);
}

static void unit_stop(void)
{
}


UNITTEST_START

  check_set("s1", 100, s1, CURL_ARRAYSIZE(s1));
  check_set("s2", 1000, s2, CURL_ARRAYSIZE(s2));

UNITTEST_STOP
