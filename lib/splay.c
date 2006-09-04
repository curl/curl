/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1997 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "splay.h"

#define compare(i,j) ((i)-(j))

/* Set this to a key value that will *NEVER* appear otherwise */
#define KEY_NOTUSED -1

/*
 * Splay using the key i (which may or may not be in the tree.) The starting
 * root is t.
 */
struct Curl_tree *Curl_splay(int i, struct Curl_tree *t)
{
  struct Curl_tree N, *l, *r, *y;
  int comp;

  if (t == NULL)
    return t;
  N.smaller = N.larger = NULL;
  l = r = &N;

  for (;;) {
    comp = compare(i, t->key);
    if (comp < 0) {
      if (t->smaller == NULL)
        break;
      if (compare(i, t->smaller->key) < 0) {
        y = t->smaller;                           /* rotate smaller */
        t->smaller = y->larger;
        y->larger = t;
        t = y;
        if (t->smaller == NULL)
          break;
      }
      r->smaller = t;                               /* link smaller */
      r = t;
      t = t->smaller;
    }
    else if (comp > 0) {
      if (t->larger == NULL)
        break;
      if (compare(i, t->larger->key) > 0) {
        y = t->larger;                          /* rotate larger */
        t->larger = y->smaller;
        y->smaller = t;
        t = y;
        if (t->larger == NULL)
          break;
      }
      l->larger = t;                              /* link larger */
      l = t;
      t = t->larger;
    }
    else
      break;
  }

  l->larger = t->smaller;                                /* assemble */
  r->smaller = t->larger;
  t->smaller = N.larger;
  t->larger = N.smaller;

  return t;
}

/* Insert key i into the tree t.  Return a pointer to the resulting tree or
   NULL if something went wrong. */
struct Curl_tree *Curl_splayinsert(int i,
                                   struct Curl_tree *t,
                                   struct Curl_tree *node)
{
  if (node == NULL)
    return t;

  if (t != NULL) {
    t = Curl_splay(i,t);
    if (compare(i, t->key)==0) {
      /* There already exists a node in the tree with the very same key. Build
         a linked list of nodes. We make the new 'node' struct the new master
         node and make the previous node the first one in the 'same' list. */

      node->same = t;
      node->key = i;
      node->smaller = t->smaller;
      node->larger = t->larger;

      t->smaller = node; /* in the sub node for this same key, we use the
                            smaller pointer to point back to the master
                            node */

      t->key = KEY_NOTUSED; /* and we set the key in the sub node to NOTUSED
                               to quickly identify this node as a subnode */

      return node; /* new root node */
    }
  }

  if (t == NULL) {
    node->smaller = node->larger = NULL;
  }
  else if (compare(i, t->key) < 0) {
    node->smaller = t->smaller;
    node->larger = t;
    t->smaller = NULL;

  }
  else {
    node->larger = t->larger;
    node->smaller = t;
    t->larger = NULL;
  }
  node->key = i;

  node->same = NULL; /* no identical node (yet) */
  return node;
}

#if 0
/* Deletes 'i' from the tree if it's there (with an exact match). Returns a
   pointer to the resulting tree.

   Function not used in libcurl.
*/
struct Curl_tree *Curl_splayremove(int i, struct Curl_tree *t,
                                   struct Curl_tree **removed)
{
  struct Curl_tree *x;

  *removed = NULL; /* default to no removed */

  if (t==NULL)
    return NULL;

  t = Curl_splay(i,t);
  if (compare(i, t->key) == 0) {               /* found it */

    /* FIRST! Check if there is a list with identical sizes */
    if((x = t->same)) {
      /* there is, pick one from the list */

      /* 'x' is the new root node */

      x->key = t->key;
      x->larger = t->larger;
      x->smaller = t->smaller;

      *removed = t;
      return x; /* new root */
    }

    if (t->smaller == NULL) {
      x = t->larger;
    }
    else {
      x = Curl_splay(i, t->smaller);
      x->larger = t->larger;
    }
    *removed = t;

    return x;
  }
  else
    return t;                         /* It wasn't there */
}
#endif

/* Finds and deletes the best-fit node from the tree. Return a pointer to the
   resulting tree.  best-fit means the node with the given or lower number */
struct Curl_tree *Curl_splaygetbest(int i, struct Curl_tree *t,
                                    struct Curl_tree **removed)
{
  struct Curl_tree *x;

  if (!t) {
    *removed = NULL; /* none removed since there was no root */
    return NULL;
  }

  t = Curl_splay(i,t);
  if(compare(i, t->key) < 0) {
    /* too big node, try the smaller chain */
    if(t->smaller)
      t=Curl_splay(t->smaller->key, t);
    else {
      /* fail */
      *removed = NULL;
      return t;
    }
  }

  if (compare(i, t->key) >= 0) {               /* found it */
    /* FIRST! Check if there is a list with identical sizes */
    x = t->same;
    if(x) {
      /* there is, pick one from the list */

      /* 'x' is the new root node */

      x->key = t->key;
      x->larger = t->larger;
      x->smaller = t->smaller;

      *removed = t;
      return x; /* new root */
    }

    if (t->smaller == NULL) {
      x = t->larger;
    }
    else {
      x = Curl_splay(i, t->smaller);
      x->larger = t->larger;
    }
    *removed = t;

    return x;
  }
  else {
    *removed = NULL; /* no match */
    return t;        /* It wasn't there */
  }
}


/* Deletes the very node we point out from the tree if it's there. Stores a
   pointer to the new resulting tree in 'newroot'.

   Returns zero on success and non-zero on errors! TODO: document error codes.
   When returning error, it does not touch the 'newroot' pointer.

   NOTE: when the last node of the tree is removed, there's no tree left so
   'newroot' will be made to point to NULL.
*/
int Curl_splayremovebyaddr(struct Curl_tree *t,
                           struct Curl_tree *remove,
                           struct Curl_tree **newroot)
{
  struct Curl_tree *x;

  if (!t || !remove)
    return 1;

  if(KEY_NOTUSED == remove->key) {
    /* Key set to NOTUSED means it is a subnode within a 'same' linked list
       and thus we can unlink it easily. The 'smaller' link of a subnode
       links to the parent node. */
    if (remove->smaller == NULL)
      return 3;

    remove->smaller->same = remove->same;
    if(remove->same)
      remove->same->smaller = remove->smaller;

    /* Ensures that double-remove gets caught. */
    remove->smaller = NULL;

    /* voila, we're done! */
    *newroot = t; /* return the same root */
    return 0;
  }

  t = Curl_splay(remove->key, t);

  /* First make sure that we got the same root node as the one we want
     to remove, as otherwise we might be trying to remove a node that
     isn't actually in the tree.

     We cannot just compare the keys here as a double remove in quick
     succession of a node with key != KEY_NOTUSED && same != NULL
     could return the same key but a different node. */
  if(t != remove)
    return 2;

  /* Check if there is a list with identical sizes, as then we're trying to
     remove the root node of a list of nodes with identical keys. */
  x = t->same;
  if(x) {
    /* 'x' is the new root node, we just make it use the root node's
       smaller/larger links */

    x->key = t->key;
    x->larger = t->larger;
    x->smaller = t->smaller;
  }
  else {
    /* Remove the root node */
    if (t->smaller == NULL)
      x = t->larger;
    else {
      x = Curl_splay(remove->key, t->smaller);
      x->larger = t->larger;
    }
  }

  *newroot = x; /* store new root pointer */

  return 0;
}

#ifdef CURLDEBUG

void Curl_splayprint(struct Curl_tree * t, int d, char output)
{
  struct Curl_tree *node;
  int i;
  int count;
  if (t == NULL)
    return;

  Curl_splayprint(t->larger, d+1, output);
  for (i=0; i<d; i++)
    if(output)
      printf("  ");

  if(output) {
    printf("%d[%d]", t->key, i);
  }

  for(count=0, node = t->same; node; node = node->same, count++)
    ;

  if(output) {
    if(count)
      printf(" [%d more]\n", count);
    else
      printf("\n");
  }

  Curl_splayprint(t->smaller, d+1, output);
}
#endif

#ifdef TEST_SPLAY

/*#define TEST2 */
#define MAX 50
#define TEST2

/* A sample use of these functions.  Start with the empty tree, insert some
   stuff into it, and then delete it */
int main(int argc, char **argv)
{
  struct Curl_tree *root, *t;
  void *ptrs[MAX];
  int adds=0;
  int rc;

  long sizes[]={
    50, 60, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200, 300,
    220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200,
    300, 220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120,
    200, 300, 220, 80, 90};
  int i;
  root = NULL;              /* the empty tree */

  for (i = 0; i < MAX; i++) {
    int key;
    ptrs[i] = t = (struct Curl_tree *)malloc(sizeof(struct Curl_tree));

#ifdef TEST2
    key = sizes[i];
#elif defined(TEST1)
    key = (541*i)%1023;
#elif defined(TEST3)
    key = 100;
#endif

    t->payload = (void *)key; /* for simplicity */
    if(!t) {
      puts("out of memory!");
      return 0;
    }
    root = Curl_splayinsert(key, root, t);
  }

#if 0
  puts("Result:");
  Curl_splayprint(root, 0, 1);
#endif

#if 1
  for (i = 0; i < MAX; i++) {
    int rem = (i+7)%MAX;
    struct Curl_tree *r;
    printf("Tree look:\n");
    Curl_splayprint(root, 0, 1);
    printf("remove pointer %d, payload %d\n", rem,
           (int)((struct Curl_tree *)ptrs[rem])->payload);
    rc = Curl_splayremovebyaddr(root, (struct Curl_tree *)ptrs[rem], &root);
    if(rc)
      /* failed! */
      printf("remove %d failed!\n", rem);
  }
#endif

  return 0;
}

#endif /* TEST_SPLAY */
