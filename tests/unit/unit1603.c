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
#include "hash.h"

static const size_t slots = 3;

static void t1603_mydtor(void *p)
{
  /* Data are statically allocated */
  (void)p;
}

static size_t elem_dtor_calls;

static void my_elem_dtor(void *key, size_t key_len, void *p)
{
  (void)p;
  (void)key;
  (void)key_len;
  ++elem_dtor_calls;
}

static CURLcode t1603_setup(struct Curl_hash *hash_static)
{
  Curl_hash_init(hash_static, slots, CURL_HASH_TYPE_BYTES, t1603_mydtor);
  return CURLE_OK;
}

static void t1603_stop(struct Curl_hash *hash_static)
{
  Curl_hash_destroy(hash_static);
}

static void t1603_test_socket_type(void)
{
  struct Curl_hash hash;
  curl_socket_t key = 1;
  curl_socket_t collision = (curl_socket_t)(slots + 1);
  int value = 1;
  int collision_value = 2;
  int replacement_value = 3;
#if SIZEOF_CURL_SOCKET_T > 4
  curl_socket_t high_key = ((curl_socket_t)1 << 32) + 1;
  int high_value = 4;
#endif

  Curl_hash_init(&hash, slots, CURL_HASH_TYPE_SOCKET, t1603_mydtor);
  fail_unless(!Curl_hash_add(&hash, &key, sizeof(key) - 1, &value),
              "invalid socket key length was accepted");
  fail_unless(!hash.table, "invalid socket key allocated a hash table");
  fail_unless(!Curl_hash_pick(&hash, &key, sizeof(key) - 1),
              "invalid socket key lookup succeeded");
  fail_unless(Curl_hash_delete(&hash, &key, sizeof(key) - 1),
              "invalid socket key deletion succeeded");
  fail_unless(Curl_hash_add(&hash, &key, sizeof(key), &value) == &value,
              "socket key insertion failed");
  fail_unless(hash.table && hash.table[1],
              "socket key used the wrong hash slot");
  fail_unless(Curl_hash_add(&hash, &key, sizeof(key), &replacement_value) ==
              &replacement_value, "socket key replacement failed");
  fail_unless(Curl_hash_count(&hash) == 1,
              "socket key replacement changed the hash count");
  fail_unless(Curl_hash_pick(&hash, &key, sizeof(key)) == &replacement_value,
              "socket key replacement lookup failed");
  fail_unless(Curl_hash_add(&hash, &collision, sizeof(collision),
                            &collision_value) == &collision_value,
              "colliding socket key insertion failed");
  fail_unless(Curl_hash_count(&hash) == 2, "wrong socket hash count");
  fail_unless(Curl_hash_pick(&hash, &collision, sizeof(collision)) ==
              &collision_value, "colliding socket key lookup failed");
#if SIZEOF_CURL_SOCKET_T > 4
  fail_unless(Curl_hash_add(&hash, &high_key, sizeof(high_key), &high_value) ==
              &high_value, "wide socket key insertion failed");
  fail_unless(hash.table && hash.table[2],
              "wide socket key used the wrong hash slot");
  fail_unless(Curl_hash_count(&hash) == 3, "wrong wide socket hash count");
  fail_unless(Curl_hash_pick(&hash, &high_key, sizeof(high_key)) ==
              &high_value, "wide socket key lookup failed");
#endif
  fail_unless(!Curl_hash_delete(&hash, &key, sizeof(key)),
              "socket key deletion failed");
  fail_unless(!Curl_hash_pick(&hash, &key, sizeof(key)),
              "deleted socket key was found");
  fail_unless(Curl_hash_pick(&hash, &collision, sizeof(collision)) ==
              &collision_value, "collision was lost after deletion");
  Curl_hash_destroy(&hash);
}

static CURLcode test_unit1603(const char *arg)
{
  struct Curl_hash hash_static;

  UNITTEST_BEGIN(t1603_setup(&hash_static))

  char key1[] = "key1";
  char key2[] = "key2b";
  char key3[] = "key3";
  char key4[] = "key4";
  char notakey[] = "notakey";
  const char *nodep;
  int rc;

  /* Ensure the key hashes are as expected in order to test both hash
     collisions and a full table. Unfortunately, the hashes can vary
     between architectures. */
  if(Curl_hash_str(key1, strlen(key1), slots) != 1 ||
     Curl_hash_str(key2, strlen(key2), slots) != 0 ||
     Curl_hash_str(key3, strlen(key3), slots) != 2 ||
     Curl_hash_str(key4, strlen(key4), slots) != 1)
    curl_mfprintf(stderr,
                  "Warning: hashes are not computed as expected on this "
                  "architecture; test coverage is less comprehensive\n");

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

  /* Add element with own destructor */
  nodep = Curl_hash_add2(&hash_static, &key1, strlen(key1), &key1,
                         my_elem_dtor);
  fail_unless(nodep, "add2 insertion into hash failed");
  fail_unless(elem_dtor_calls == 0, "element destructor count should be 0");
  /* Add it again, should invoke destructor on first */
  nodep = Curl_hash_add2(&hash_static, &key1, strlen(key1), &key1,
                         my_elem_dtor);
  fail_unless(nodep, "add2 again, insertion into hash failed");
  fail_unless(elem_dtor_calls == 1, "element destructor count should be 1");
  /* remove, should invoke destructor */
  rc = Curl_hash_delete(&hash_static, &key1, strlen(key1));
  fail_unless(rc == 0, "hash delete failed");
  fail_unless(elem_dtor_calls == 2, "element destructor count should be 1");

  /* Clean up */
  Curl_hash_clean(&hash_static);

  t1603_test_socket_type();

  UNITTEST_END(t1603_stop(&hash_static))
}
