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
#include "splay.h"

static void splayprint(struct Curl_tree *t, int d, char output)
{
  struct Curl_tree *node;
  int i;
  int count;
  if(!t)
    return;

  splayprint(t->larger, d + 1, output);
  for(i = 0; i < d; i++)
    if(output)
      curl_mprintf("  ");

  if(output) {
    curl_mprintf("0.%ld[%d]", (long)t->key, i);
  }

  for(count = 0, node = t->same; node; node = node->same, count++)
    ;

  if(output) {
    if(count)
      curl_mprintf(" [%d more]\n", count);
    else
      curl_mprintf("\n");
  }

  splayprint(t->smaller, d + 1, output);
}

static void test_timeouts_nonzero_usec_base(void)
{
  struct Curl_timeouts timeouts;
  struct Curl_tree node;
  struct curltime base;
  struct curltime deadline;
  struct curltime now;
  timediff_t original_deadline_offset;
  timediff_t original_now_offset;
  timediff_t deadline_offset;
  timediff_t now_offset;
  timediff_t expire_offset;
  uint32_t mid;
  int timeout_ms;

  base.tv_sec = 10;
  base.tv_usec = 750000;
  deadline.tv_sec = 12;
  deadline.tv_usec = 250000;
  now.tv_sec = 11;
  now.tv_usec = 100000;

  original_deadline_offset = curlx_ptimediff_us(&deadline, &base);
  original_now_offset = curlx_ptimediff_us(&now, &base);

  Curl_timeouts_init(&timeouts, &base);
  deadline_offset = Curl_timeouts_offset_us(&timeouts, &deadline);
  now_offset = Curl_timeouts_offset_us(&timeouts, &now);

  fail_unless(deadline_offset - original_deadline_offset == base.tv_usec,
              "deadline offset did not shift by the base microseconds");
  fail_unless(now_offset - original_now_offset == base.tv_usec,
              "now offset did not shift by the base microseconds");

  memset(&node, 0, sizeof(node));
  timeouts.tree = Curl_splayinsert(deadline_offset, timeouts.tree, &node, 42);
  timeout_ms = Curl_timeouts_next_ms(&timeouts, &now, &expire_offset, &mid);

  fail_unless(timeout_ms == 1150, "timeout changed with whole-second base");
  fail_unless(expire_offset == deadline_offset, "wrong expiry offset");
  fail_unless(mid == 42, "wrong timeout id");
}

static CURLcode test_unit1309(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

/* number of nodes to add to the splay tree */
#define NUM_NODES 50

  struct Curl_tree *root, *removed;
  struct Curl_tree nodes[NUM_NODES * 3];
  int rc;
  size_t i, j;
  timediff_t tv_now = 0, timeout_last;
  root = NULL; /* the empty tree */

  /* add nodes */
  for(i = 0; i < NUM_NODES; i++) {
    timediff_t key;

    key = (541 * i) % 1023;
    root = Curl_splayinsert(key, root, &nodes[i], (uint32_t)key);
    fail_unless(nodes[i].registered, "node should have been registered");
  }

  puts("Result:");
  splayprint(root, 0, 1);

  for(i = 0; i < NUM_NODES; i++) {
    size_t rem = (i + 7) % NUM_NODES;
    curl_mprintf("Tree look:\n");
    splayprint(root, 0, 1);
    curl_mprintf("remove node %d, payload %u\n", (int)rem,
                 Curl_splayget(&nodes[rem]));
    rc = Curl_splayremove(root, &nodes[rem], &root);
    if(rc) {
      /* failed! */
      curl_mprintf("remove %d failed!\n", (int)rem);
      fail("remove");
    }
    fail_unless(!nodes[rem].registered, "node should not be registered");
    rc = Curl_splayremove(root, &nodes[rem], &root);
    if(!rc) {
      /* failed! */
      curl_mprintf("double remove %d did not fail!\n", (int)rem);
      fail("double remove");
    }
  }

  fail_unless(!root, "tree not empty after removing all nodes");

  /* rebuild tree */
  for(i = 0; i < NUM_NODES; i++) {
    timediff_t key;

    key = (541 * i) % 1023;

    /* add some nodes with the same key */
    for(j = 0; j <= i % 3; j++) {
      root = Curl_splayinsert(key, root, &nodes[(i * 3) + j],
                              (uint32_t)(key * 10 + j));
    }
  }

  removed = NULL;
  for(i = 0; i <= 1100; i += 100) {
    curl_mprintf("Removing nodes not larger than %d\n", (int)i);
    tv_now = i;
    root = Curl_splaygetbest(tv_now, root, &removed);
    while(removed) {
      curl_mprintf("removed payload %u[%u]\n",
                   Curl_splayget(removed) / 10,
                   Curl_splayget(removed) % 10);
      root = Curl_splaygetbest(tv_now, root, &removed);
    }
  }

  fail_unless(!root, "tree not empty when it should be");

  /* rebuild tree with duplicate values */
  for(i = 0; i < NUM_NODES; i++) {
    timediff_t key = (541 * i) % 128;
    root = Curl_splayinsert(key, root, &nodes[i], (uint32_t)i);
  }

  removed = NULL;
  timeout_last = -1;
  for(i = 0; i <= 128; i += 32) {
    curl_mprintf("Removing nodes not larger than %d\n", (int)i);
    root = Curl_splaygetbest(i, root, &removed);
    while(removed) {
      curl_mprintf("removed payload %u[timeout=%d]\n",
                   Curl_splayget(removed), (int)removed->key);
      if(removed->key < timeout_last) {
        /* failed! */
        curl_mprintf("remove timeout %d is smaller than last %d!\n",
                    (int)removed->key, (int)timeout_last);
        fail("wrong timeout order");
      }
      timeout_last = removed->key;
      root = Curl_splaygetbest(i, root, &removed);
    }
  }

  fail_unless(!root, "tree not empty when it should be");

  test_timeouts_nonzero_usec_base();

  UNITTEST_END_SIMPLE
}
