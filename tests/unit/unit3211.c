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
#include "uint-bset.h"
#include "uint-hashset.h"
#include "curl_trc.h"

static void t3211_check_bset(const char *name, uint32_t capacity,
                             const uint32_t *s, size_t slen)
{
  struct uint32_bset bset;
  size_t i, j;
  uint32_t n, c;

  curl_mfprintf(stderr, "test %s, capacity=%u, %zu numbers\n",
                name, capacity, slen);
  Curl_uint32_bset_init(&bset);
  fail_unless(!Curl_uint32_bset_resize(&bset, capacity), "bset resize failed");
  c = uint32_bset_capacity(&bset);
  fail_unless(c == (((capacity + 63) / 64) * 64), "wrong capacity");

  Curl_uint32_bset_clear(&bset);
  c = Curl_uint32_bset_count(&bset);
  fail_unless(c == 0, "set count is not 0");

  for(i = 0; i < slen; ++i) { /* add all */
    fail_unless(Curl_uint32_bset_add(&bset, s[i]), "failed to add");
    for(j = i + 1; j < slen; ++j)
      fail_unless(!Curl_uint32_bset_contains(&bset, s[j]),
                  "unexpectedly found");
  }

  for(i = 0; i < slen; ++i) { /* all present */
    fail_unless(Curl_uint32_bset_contains(&bset, s[i]),
                "failed presence check");
  }

  /* iterator over all numbers */
  fail_unless(Curl_uint32_bset_first(&bset, &n), "first failed");
  fail_unless(n == s[0], "first not correct number");
  for(i = 1; i < slen; ++i) {
    fail_unless(Curl_uint32_bset_next(&bset, n, &n), "next failed");
    if(n != s[i]) {
      curl_mfprintf(stderr, "expected next to be %u, not %u\n", s[i], n);
      fail_unless(n == s[i], "next not correct number");
    }
  }

  /* Adding capacity number does not work (0 - capacity-1) */
  c = uint32_bset_capacity(&bset);
  fail_unless(!Curl_uint32_bset_add(&bset, c), "add out of range worked");
  /* The count it correct */
  c = Curl_uint32_bset_count(&bset);
  fail_unless(c == slen, "set count is wrong");

  for(i = 0; i < slen; i += 2) { /* remove every 2nd */
    Curl_uint32_bset_remove(&bset, s[i]);
    fail_unless(!Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly found");
  }
  for(i = 1; i < slen; i += 2) { /* others still there */
    fail_unless(Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly gone");
  }
  /* The count is half */
  c = Curl_uint32_bset_count(&bset);
  fail_unless(c == slen / 2, "set count is wrong");

  Curl_uint32_bset_clear(&bset);
  c = Curl_uint32_bset_count(&bset);
  fail_unless(c == 0, "set count is not 0");
  for(i = 0; i < slen; i++) { /* none present any longer */
    fail_unless(!Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly there");
  }

  for(i = 0; i < slen; ++i) { /* add all again */
    fail_unless(Curl_uint32_bset_add(&bset, s[i]), "failed to add");
  }

  fail_unless(!Curl_uint32_bset_resize(&bset, capacity * 2),
              "resize double failed");
  for(i = 0; i < slen; i++) { /* all still present after resize */
    fail_unless(Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly lost");
  }

  fail_unless(!Curl_uint32_bset_resize(&bset, capacity), "resize back failed");
  for(i = 0; i < slen; i++)  /* all still present after resize back */
    fail_unless(Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly lost");

  fail_unless(!Curl_uint32_bset_resize(&bset, capacity / 2),
              "resize half failed");
  /* halved the size, what numbers remain in set? */
  c = uint32_bset_capacity(&bset);
  n = 0;
  for(i = 0; i < slen; ++i) {
    if(s[i] < c)
      ++n;
  }
  fail_unless(n == Curl_uint32_bset_count(&bset), "set count(halved) wrong");
  for(i = 0; i < n; i++)  /* still present after resize half */
    fail_unless(Curl_uint32_bset_contains(&bset, s[i]), "unexpectedly lost");

  Curl_uint32_bset_destroy(&bset);
}

static bool t3211_strcmp(const char *s1, const char *s2)
{
  if(s1 && s2)
    return strcmp(s1, s2);
  return s1 == s2;
}

static void t3211_check_strset1(void)
{
  struct u8_strset set;
  char buf[128];
  CURLcode result;
  uint8_t i, idx;
  int j;

  Curl_u8_strset_init(&set);
  fail_unless(!Curl_u8_strset_count(&set), "initial strset not empty");

  result = Curl_u8_strset_set(&set, 0, "123");
  fail_unless(!result, "add1 failed");
  fail_unless(Curl_u8_strset_get(&set, 0), "get failed");
  fail_unless(!t3211_strcmp("123", Curl_u8_strset_get(&set, 0)), "wrong get1");
  result = Curl_u8_strset_set(&set, 0, "456");
  fail_unless(!result, "add2 failed");
  fail_unless(!t3211_strcmp("456", Curl_u8_strset_get(&set, 0)), "wrong get2");
  Curl_u8_strset_unset(&set, 0);
  fail_unless(!Curl_u8_strset_get(&set, 0), "unset failed");

  /* Initial size is 8, add 8 hash collisions */
  for(i = 0; i < 8; ++i) {
    idx = (uint8_t)((8 * i) + 3);
    curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
    result = Curl_u8_strset_set(&set, idx, buf);
    fail_unless(!result, "loop4-add failed");
    fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
                "wrong get loop4");
  }

  /* Remove collided entry 2, check again */
  idx = (uint8_t)((8 * 2) + 3);
  Curl_u8_strset_unset(&set, idx);
  fail_unless(!Curl_u8_strset_get(&set, idx), "unset2 failed");
  for(i = 0; i < 8; ++i) {
    if(i == 2)
      continue;
    idx = (uint8_t)((8 * i) + 3);
    curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
    fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
                "wrong get loop6");
  }

  /* Add entry 2 again, check */
  idx = (uint8_t)((8 * 2) + 3);
  curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
  result = Curl_u8_strset_set(&set, idx, buf);
  fail_unless(!result, "re-add 2 failed");
  fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
              "wrong re-add 2 get");
  for(i = 0; i < 8; ++i) {
    idx = (uint8_t)((8 * i) + 3);
    curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
    fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
                "wrong get loop6");
  }

  /* Add a 9th, set grows */
  fail_unless(Curl_u8_strset_count(&set) == 8, "wrong count pre add 5");
  idx = (uint8_t)((9 * 4) + 3);
  curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
  result = Curl_u8_strset_set(&set, idx, buf);
  fail_unless(!result, "add4 failed");
  fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
              "wrong get4");
  for(i = 0; i < 9; ++i) {
    idx = (uint8_t)((8 * i) + 3);
    curl_msnprintf(buf, sizeof(buf), "str-%d", idx);
    fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, idx)),
                "wrong get loop5");
  }
  fail_unless(Curl_u8_strset_count(&set) == 9, "wrong count aftger add 5");

  Curl_u8_strset_clear(&set);

  /* Make a full set */
  for(j = 0; j <= UINT8_MAX; ++j) {
    i = (uint8_t)j;
    curl_msnprintf(buf, sizeof(buf), "str-%d", i);
    result = Curl_u8_strset_set(&set, i, buf);
    fail_unless(!result, "loop256-add failed");
    fail_unless(!t3211_strcmp(buf, Curl_u8_strset_get(&set, i)),
                "wrong get loop256");
  }

  Curl_u8_strset_clear(&set);
  fail_unless(!Curl_u8_strset_count(&set), "cleared strset not empty");
}

static CURLcode test_unit3211(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const uint32_t s1[] = {
    /* spread numbers, some at slot edges */
    0, 1, 4, 17, 63, 64, 65, 66, 90, 99,
  };
  static const uint32_t s2[] = {
    /* set with all bits in slot1 set */
    64, 65, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87,
    88, 89, 90, 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127,
  };

  t3211_check_bset("s1", 100, s1, CURL_ARRAYSIZE(s1));
  t3211_check_bset("s2", 1000, s2, CURL_ARRAYSIZE(s2));

  t3211_check_strset1();

  UNITTEST_END_SIMPLE
}
