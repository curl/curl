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
#include "slist.h"

static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct curl_slist *list = NULL;
  struct curl_slist *clone = NULL;
  struct curl_slist *item = NULL;

  /* --- curl_slist_append: append to NULL creates a new list --- */
  list = curl_slist_append(NULL, "first");
  abort_unless(list, "curl_slist_append on NULL should allocate a new list");
  fail_unless(strcmp(list->data, "first") == 0,
              "first node data should be 'first'");
  fail_unless(!list->next, "single-element list must have next == NULL");

  /* --- curl_slist_append: append a second element --- */
  list = curl_slist_append(list, "second");
  abort_unless(list, "curl_slist_append should return the list head");
  fail_unless(strcmp(list->data, "first") == 0,
              "head data must still be 'first' after second append");
  abort_unless(list->next, "list must have a second node");
  fail_unless(strcmp(list->next->data, "second") == 0,
              "second node data should be 'second'");
  fail_unless(!list->next->next, "two-element list tail must have next == NULL");

  /* --- curl_slist_append: append a third element --- */
  list = curl_slist_append(list, "third");
  abort_unless(list && list->next && list->next->next,
               "list must have three nodes after three appends");
  fail_unless(strcmp(list->next->next->data, "third") == 0,
              "third node data should be 'third'");
  fail_unless(!list->next->next->next,
              "three-element list tail must have next == NULL");

  /* --- curl_slist_append: data is copied (mutation of original is safe) --- */
  {
    char buf[16];
    struct curl_slist *copy_test;
    memcpy(buf, "mutable", 8);
    copy_test = curl_slist_append(NULL, buf);
    abort_unless(copy_test, "append of mutable buffer should succeed");
    memcpy(buf, "XXXXXXX", 7); /* mutate original */
    fail_unless(strcmp(copy_test->data, "mutable") == 0,
                "slist must own a copy, not a reference to the original");
    curl_slist_free_all(copy_test);
  }

  /* --- Curl_slist_append_nodup: takes ownership of a malloc'd string --- */
  {
    char *owned = strdup("owned");
    struct curl_slist *nodup_list;
    abort_unless(owned, "strdup must succeed");
    nodup_list = Curl_slist_append_nodup(NULL, owned);
    abort_unless(nodup_list, "Curl_slist_append_nodup should succeed");
    fail_unless(nodup_list->data == owned,
                "nodup variant must store the exact pointer, not a copy");
    curl_slist_free_all(nodup_list);
  }

  /* --- Curl_slist_duplicate: NULL input returns NULL --- */
  clone = Curl_slist_duplicate(NULL);
  fail_unless(!clone, "duplicating NULL list should return NULL");

  /* --- Curl_slist_duplicate: clones all nodes with independent storage --- */
  clone = Curl_slist_duplicate(list);
  abort_unless(clone, "Curl_slist_duplicate should return a valid list");

  /* verify each node matches by value */
  item = clone;
  fail_unless(strcmp(item->data, "first") == 0,
              "cloned node 1 should be 'first'");
  abort_unless(item->next, "clone must have at least 2 nodes");
  item = item->next;
  fail_unless(strcmp(item->data, "second") == 0,
              "cloned node 2 should be 'second'");
  abort_unless(item->next, "clone must have 3 nodes");
  item = item->next;
  fail_unless(strcmp(item->data, "third") == 0,
              "cloned node 3 should be 'third'");
  fail_unless(!item->next, "cloned list must end after 3 nodes");

  /* verify the clone is independent: mutating original does not affect clone */
  fail_unless(clone->data != list->data,
              "clone nodes must use separate storage from the original");

  /* --- curl_slist_free_all: freeing NULL is a no-op --- */
  curl_slist_free_all(NULL); /* must not crash */

  /* --- curl_slist_free_all: frees a single-element list --- */
  {
    struct curl_slist *single = curl_slist_append(NULL, "only");
    abort_unless(single, "single-element list must be created");
    curl_slist_free_all(single); /* must not crash or leak */
  }

  /* cleanup */
  curl_slist_free_all(clone);
  curl_slist_free_all(list);

  UNITTEST_END_SIMPLE
}
