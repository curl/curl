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
#include "uint-table.h"
#include "curl_trc.h"
#include "unitprotos.h"

#define TBL_SIZE    100

static CURLcode t3212_setup(struct uint_tbl *tbl)
{
  Curl_uint_tbl_init(tbl, NULL);
  return Curl_uint_tbl_resize(tbl, TBL_SIZE);
}

static void t3212_stop(struct uint_tbl *tbl)
{
  Curl_uint_tbl_destroy(tbl);
}

static CURLcode test_unit3212(const char *arg)
{
  struct uint_tbl tbl;
  int dummy;

  UNITTEST_BEGIN(t3212_setup(&tbl))

  unsigned int i, key, n;
  void *entry;

  fail_unless(Curl_uint_tbl_capacity(&tbl) == TBL_SIZE, "wrong capacity");

  for(i = 0; i < TBL_SIZE; ++i) {
    fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add");
    fail_unless(key == i, "unexpected key assigned");
  }
  /* table should be full now */
  fail_unless(Curl_uint_tbl_count(&tbl) == TBL_SIZE, "wrong count");
  fail_unless(!Curl_uint_tbl_add(&tbl, &dummy, &key), "could add more");
  /* remove every 2nd entry, from full table */
  n = TBL_SIZE;
  for(i = 0; i < TBL_SIZE; i += 2) {
    Curl_uint_tbl_remove(&tbl, i);
    --n;
    fail_unless(Curl_uint_tbl_count(&tbl) == n, "wrong count after remove");
  }
  /* remove same again, should not change count */
  for(i = 0; i < TBL_SIZE; i += 2) {
    Curl_uint_tbl_remove(&tbl, i);
    fail_unless(Curl_uint_tbl_count(&tbl) == n, "wrong count after remove");
  }
  /* still contains all odd entries */
  for(i = 1; i < TBL_SIZE; i += 2) {
    fail_unless(Curl_uint_tbl_contains(&tbl, i), "does not contain");
    fail_unless(Curl_uint_tbl_get(&tbl, i) == &dummy,
                "does not contain dummy");
  }
  /* get the first key */
  fail_unless(Curl_uint_tbl_first(&tbl, &key, &entry), "first failed");
  fail_unless(key == 1, "unexpected first key");
  fail_unless(entry == &dummy, "unexpected first entry");
  /* get the second key */
  fail_unless(Curl_uint_tbl_next(&tbl, 1, &key, &entry), "next1 failed");
  fail_unless(key == 3, "unexpected second key");
  fail_unless(entry == &dummy, "unexpected second entry");
  /* get the key after 42 */
  fail_unless(Curl_uint_tbl_next(&tbl, 42, &key, &entry), "next42 failed");
  fail_unless(key == 43, "unexpected next42 key");
  fail_unless(entry == &dummy, "unexpected next42 entry");

  /* double capacity */
  n = Curl_uint_tbl_count(&tbl);
  fail_unless(!Curl_uint_tbl_resize(&tbl, TBL_SIZE * 2),
              "error doubling size");
  fail_unless(Curl_uint_tbl_count(&tbl) == n, "wrong resize count");
  /* resize to half of original */
  fail_unless(!Curl_uint_tbl_resize(&tbl, TBL_SIZE / 2), "error halving size");
  fail_unless(Curl_uint_tbl_count(&tbl) == n / 2, "wrong half size count");
  for(i = 1; i < TBL_SIZE / 2; i += 2) {
    fail_unless(Curl_uint_tbl_contains(&tbl, i), "does not contain");
    fail_unless(Curl_uint_tbl_get(&tbl, i) == &dummy,
                "does not contain dummy");
  }
  /* clear */
  Curl_uint_tbl_clear(&tbl);
  fail_unless(!Curl_uint_tbl_count(&tbl), "count not 0 after clear");
  for(i = 0; i < TBL_SIZE / 2; ++i) {
    fail_unless(!Curl_uint_tbl_contains(&tbl, i), "does contain, should not");
  }
  /* add after clear gets key 0 again */
  fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add");
  fail_unless(key == 0, "unexpected key assigned");
  /* remove it again and add, should get key 1 */
  Curl_uint_tbl_remove(&tbl, key);
  fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add");
  fail_unless(key == 1, "unexpected key assigned");
  /* clear, fill, remove one, add, should get the removed key again */
  Curl_uint_tbl_clear(&tbl);
  for(i = 0; i < Curl_uint_tbl_capacity(&tbl); ++i)
    fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add");
  fail_unless(!Curl_uint_tbl_add(&tbl, &dummy, &key), "add on full");
  Curl_uint_tbl_remove(&tbl, 17);
  fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add again");
  fail_unless(key == 17, "unexpected key assigned");
  /* and again, triggering key search wrap around */
  Curl_uint_tbl_remove(&tbl, 17);
  fail_unless(Curl_uint_tbl_add(&tbl, &dummy, &key), "failed to add again");
  fail_unless(key == 17, "unexpected key assigned");

  UNITTEST_END(t3212_stop(&tbl))
}
