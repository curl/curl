/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

  splayprint(t->larger, d+1, output);
  for(i=0; i<d; i++)
    if(output)
      printf("  ");

  if(output) {
    printf("%ld.%ld[%d]", (long)t->key.tv_sec,
           (long)t->key.tv_usec, i);
  }

  for(count=0, node = t->same; node; node = node->same, count++)
    ;

  if(output) {
    if(count)
      printf(" [%d more]\n", count);
    else
      printf("\n");
  }

  splayprint(t->smaller, d+1, output);
}

UNITTEST_START

/* number of nodes to add to the splay tree */
#define NUM_NODES 50

  struct Curl_tree *root;
  struct Curl_tree nodes[NUM_NODES];
  int rc;
  int i;
  root = NULL;              /* the empty tree */

  for(i = 0; i < NUM_NODES; i++) {
    struct timeval key;

    key.tv_sec = 0;
    key.tv_usec = (541*i)%1023;

    nodes[i].payload = (void *)key.tv_usec; /* for simplicity */
    root = Curl_splayinsert(key, root, &nodes[i]);
  }

  puts("Result:");
  splayprint(root, 0, 1);

  for(i = 0; i < NUM_NODES; i++) {
    int rem = (i+7)%NUM_NODES;
    printf("Tree look:\n");
    splayprint(root, 0, 1);
    printf("remove pointer %d, payload %ld\n", rem,
           (long)(nodes[rem].payload));
    rc = Curl_splayremovebyaddr(root, &nodes[rem], &root);
    if(rc) {
      /* failed! */
      printf("remove %d failed!\n", rem);
      fail("remove");
    }
  }

UNITTEST_STOP




