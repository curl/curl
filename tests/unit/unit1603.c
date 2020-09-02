/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2015 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"

#include "memdebug.h" /* LAST include file */

static struct Curl_hash hash_static;
static const int slots = 3;

static void mydtor(void *p)
{
  /* Data are statically allocated */
 (void)p; /* unused */
}

static CURLcode unit_setup(void)
{
  return Curl_hash_init(&hash_static, slots, Curl_hash_str,
                        Curl_str_key_compare, mydtor);
}

static void unit_stop(void)
{
  Curl_hash_destroy(&hash_static);
}

UNITTEST_START
  char key1[] = "key1";
  char key2[] = "key2b";
  char key3[] = "key3";
  char key4[] = "key4";
  char notakey[] = "notakey";
  char *nodep;
  int rc;

  /* Ensure the key hashes are as expected in order to test both hash
     collisions and a full table. Unfortunately, the hashes can vary
     between architectures. */
  if(Curl_hash_str(key1, strlen(key1), slots) != 1 ||
     Curl_hash_str(key2, strlen(key2), slots) != 0 ||
     Curl_hash_str(key3, strlen(key3), slots) != 2 ||
     Curl_hash_str(key4, strlen(key4), slots) != 1)
    fprintf(stderr, "Warning: hashes are not computed as expected on this "
            "architecture; test coverage will be less comprehensive\n");

  nodep = Curl_hash_add(&hash_static, &key1, strlen(key1), &key1);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(nodep == key1, "hash retrieval failed");

  nodep = Curl_hash_add(&hash_static, &key2, strlen(key2), &key2);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key2, strlen(key2));
  fail_unless(nodep == key2, "hash retrieval failed");

  nodep = Curl_hash_add(&hash_static, &key3, strlen(key3), &key3);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key3, strlen(key3));
  fail_unless(nodep == key3, "hash retrieval failed");

  /* The fourth element exceeds the number of slots & collides */
  nodep = Curl_hash_add(&hash_static, &key4, strlen(key4), &key4);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(nodep == key4, "hash retrieval failed");

  /* Make sure all elements are still accessible */
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(nodep == key1, "hash retrieval failed");
  nodep = Curl_hash_pick(&hash_static, &key2, strlen(key2));
  fail_unless(nodep == key2, "hash retrieval failed");
  nodep = Curl_hash_pick(&hash_static, &key3, strlen(key3));
  fail_unless(nodep == key3, "hash retrieval failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(nodep == key4, "hash retrieval failed");

  /* Delete the second of two entries in a bucket */
  rc = Curl_hash_delete(&hash_static, &key4, strlen(key4));
  fail_unless(rc == 0, "hash delete failed");
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(nodep == key1, "hash retrieval failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(!nodep, "hash retrieval should have failed");

  /* Insert that deleted node again */
  nodep = Curl_hash_add(&hash_static, &key4, strlen(key4), &key4);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(nodep == key4, "hash retrieval failed");

  /* Delete the first of two entries in a bucket */
  rc = Curl_hash_delete(&hash_static, &key1, strlen(key1));
  fail_unless(rc == 0, "hash delete failed");
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(!nodep, "hash retrieval should have failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(nodep == key4, "hash retrieval failed");

  /* Delete the remaining one of two entries in a bucket */
  rc = Curl_hash_delete(&hash_static, &key4, strlen(key4));
  fail_unless(rc == 0, "hash delete failed");
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(!nodep, "hash retrieval should have failed");
  nodep = Curl_hash_pick(&hash_static, &key4, strlen(key4));
  fail_unless(!nodep, "hash retrieval should have failed");

  /* Delete an already deleted node */
  rc = Curl_hash_delete(&hash_static, &key4, strlen(key4));
  fail_unless(rc, "hash delete should have failed");

  /* Replace an existing node */
  nodep = Curl_hash_add(&hash_static, &key1, strlen(key1), &notakey);
  fail_unless(nodep, "insertion into hash failed");
  nodep = Curl_hash_pick(&hash_static, &key1, strlen(key1));
  fail_unless(nodep == notakey, "hash retrieval failed");

  /* Make sure all remaining elements are still accessible */
  nodep = Curl_hash_pick(&hash_static, &key2, strlen(key2));
  fail_unless(nodep == key2, "hash retrieval failed");
  nodep = Curl_hash_pick(&hash_static, &key3, strlen(key3));
  fail_unless(nodep == key3, "hash retrieval failed");

  /* Clean up */
  Curl_hash_clean(&hash_static);

UNITTEST_STOP
