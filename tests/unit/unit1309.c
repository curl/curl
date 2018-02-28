/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "splay.h"
#include "warnless.h"


static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

static void splayprint(struct Curl_tree * t, int d, char output)
{
  struct Curl_tree *node;
  int i;
  int count;
  if(t == NULL)
    return;

  splayprint(t->larger, d + 1, output);
  for(i = 0; i<d; i++)
    if(output)
      printf("  ");

  if(output) {
    printf("%ld.%ld[%d]", (long)t->key.tv_sec,
           (long)t->key.tv_usec, i);
  }

  for(count = 0, node = t->samen; node != t; node = node->samen, count++)
    ;

  if(output) {
    if(count)
      printf(" [%d more]\n", count);
    else
      printf("\n");
  }

  splayprint(t->smaller, d + 1, output);
}

UNITTEST_START

/* number of nodes to add to the splay tree */
#define NUM_NODES 50

  struct Curl_tree *root, *removed;
  struct Curl_tree nodes[NUM_NODES*3];
  int rc;
  int i, j;
  struct curltime tv_now = {0, 0};
  root = NULL;              /* the empty tree */

  /* add nodes */
  for(i = 0; i < NUM_NODES; i++) {
    struct curltime key;
    size_t payload;

    key.tv_sec = 0;
    key.tv_usec = (541*i)%1023;
    payload = (size_t) key.tv_usec;

    /* for simplicity */
    nodes[i].payload = CURLX_INTEGER_TO_POINTER_CAST(payload);
    root = Curl_splayinsert(key, root, &nodes[i]);
  }

  puts("Result:");
  splayprint(root, 0, 1);

  for(i = 0; i < NUM_NODES; i++) {
    int rem = (i + 7)%NUM_NODES;
    printf("Tree look:\n");
    splayprint(root, 0, 1);
    printf("remove pointer %d, payload %ld\n", rem,
           CURLX_POINTER_TO_INTEGER_CAST(nodes[rem].payload));
    rc = Curl_splayremovebyaddr(root, &nodes[rem], &root);
    if(rc) {
      /* failed! */
      printf("remove %d failed!\n", rem);
      fail("remove");
    }
  }

  fail_unless(root == NULL, "tree not empty after removing all nodes");

  /* rebuild tree */
  for(i = 0; i < NUM_NODES; i++) {
    struct curltime key;

    key.tv_sec = 0;
    key.tv_usec = (541*i)%1023;

    /* add some nodes with the same key */
    for(j = 0; j <= i % 3; j++) {
      size_t payload = key.tv_usec*10 + j;
      /* for simplicity */
      nodes[i * 3 + j].payload = CURLX_INTEGER_TO_POINTER_CAST(payload);
      root = Curl_splayinsert(key, root, &nodes[i * 3 + j]);
    }
  }

  removed = NULL;
  for(i = 0; i <= 1100; i += 100) {
    printf("Removing nodes not larger than %d\n", i);
    tv_now.tv_usec = i;
    root = Curl_splaygetbest(tv_now, root, &removed);
    while(removed != NULL) {
      printf("removed payload %ld[%ld]\n",
             CURLX_POINTER_TO_INTEGER_CAST(removed->payload) / 10,
             CURLX_POINTER_TO_INTEGER_CAST(removed->payload) % 10);
      root = Curl_splaygetbest(tv_now, root, &removed);
    }
  }

  fail_unless(root == NULL, "tree not empty when it should be");

UNITTEST_STOP




