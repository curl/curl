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

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"

#include "memdebug.h" /* LAST include file */

static struct Curl_hash hash_static;

static void mydtor(void *elem)
{
  int *ptr = (int *)elem;
  free(ptr);
}

static CURLcode unit_setup(void)
{
  Curl_hash_offt_init(&hash_static, 15, mydtor);
  return CURLE_OK;
}

static void unit_stop(void)
{
  Curl_hash_destroy(&hash_static);
}

UNITTEST_START
  int *value, *v;
  int *value2;
  int *nodep;

  curl_off_t key = 20;
  curl_off_t key2 = 25;


  value = malloc(sizeof(int));
  abort_unless(value != NULL, "Out of memory");
  *value = 199;
  nodep = Curl_hash_offt_set(&hash_static, key, value);
  if(!nodep)
    free(value);
  abort_unless(nodep, "insertion into hash failed");
  v = Curl_hash_offt_get(&hash_static, key);
  abort_unless(v == value, "lookup present entry failed");
  v = Curl_hash_offt_get(&hash_static, key2);
  abort_unless(!v, "lookup missing entry failed");
  Curl_hash_clean(&hash_static);

  /* Attempt to add another key/value pair */
  value2 = malloc(sizeof(int));
  abort_unless(value2 != NULL, "Out of memory");
  *value2 = 204;
  nodep = Curl_hash_offt_set(&hash_static, key2, value2);
  if(!nodep)
    free(value2);
  abort_unless(nodep, "insertion into hash failed");
  v = Curl_hash_offt_get(&hash_static, key2);
  abort_unless(v == value2, "lookup present entry failed");
  v = Curl_hash_offt_get(&hash_static, key);
  abort_unless(!v, "lookup missing entry failed");

UNITTEST_STOP
