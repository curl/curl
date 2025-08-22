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

#include "uint-hash.h"

#include "memdebug.h" /* LAST include file */

static void t1616_mydtor(unsigned int id, void *elem)
{
  int *ptr = (int *)elem;
  (void)id;
  free(ptr);
}

static CURLcode t1616_setup(struct uint_hash *hash)
{
  Curl_uint_hash_init(hash, 15, t1616_mydtor);
  return CURLE_OK;
}

static void t1616_stop(struct uint_hash *hash)
{
  Curl_uint_hash_destroy(hash);
}

static CURLcode test_unit1616(const char *arg)
{
  struct uint_hash hash;

  UNITTEST_BEGIN(t1616_setup(&hash))

  int *value, *v;
  int *value2;
  bool ok;

  unsigned int key = 20;
  unsigned int key2 = 25;

  value = malloc(sizeof(int));
  abort_unless(value != NULL, "Out of memory");
  *value = 199;
  ok = Curl_uint_hash_set(&hash, key, value);
  if(!ok)
    free(value);
  abort_unless(ok, "insertion into hash failed");
  v = Curl_uint_hash_get(&hash, key);
  abort_unless(v == value, "lookup present entry failed");
  v = Curl_uint_hash_get(&hash, key2);
  abort_unless(!v, "lookup missing entry failed");
  Curl_uint_hash_clear(&hash);

  /* Attempt to add another key/value pair */
  value2 = malloc(sizeof(int));
  abort_unless(value2 != NULL, "Out of memory");
  *value2 = 204;
  ok = Curl_uint_hash_set(&hash, key2, value2);
  if(!ok)
    free(value2);
  abort_unless(ok, "insertion into hash failed");
  v = Curl_uint_hash_get(&hash, key2);
  abort_unless(v == value2, "lookup present entry failed");
  v = Curl_uint_hash_get(&hash, key);
  abort_unless(!v, "lookup missing entry failed");

  UNITTEST_END(t1616_stop(&hash))
}
