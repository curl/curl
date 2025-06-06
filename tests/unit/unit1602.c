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

#include <curlx.h>

#include "hash.h"

#include <memdebug.h> /* LAST include file */

static struct Curl_hash t1602_hash_static;

static void t1602_mydtor(void *p)
{
  int *ptr = (int *)p;
  free(ptr);
}

static CURLcode unit_setup(void)
{
  Curl_hash_init(&t1602_hash_static, 7, Curl_hash_str,
                 curlx_str_key_compare, t1602_mydtor);
  return CURLE_OK;
}

static void unit_stop(void)
{
  Curl_hash_destroy(&t1602_hash_static);
}

UNITTEST_START
  int *value;
  int *value2;
  int *nodep;
  size_t klen = sizeof(int);

  int key = 20;
  int key2 = 25;


  value = malloc(sizeof(int));
  abort_unless(value != NULL, "Out of memory");
  *value = 199;
  nodep = Curl_hash_add(&t1602_hash_static, &key, klen, value);
  if(!nodep)
    free(value);
  abort_unless(nodep, "insertion into hash failed");
  Curl_hash_clean(&t1602_hash_static);

  /* Attempt to add another key/value pair */
  value2 = malloc(sizeof(int));
  abort_unless(value2 != NULL, "Out of memory");
  *value2 = 204;
  nodep = Curl_hash_add(&t1602_hash_static, &key2, klen, value2);
  if(!nodep)
    free(value2);
  abort_unless(nodep, "insertion into hash failed");

UNITTEST_STOP
