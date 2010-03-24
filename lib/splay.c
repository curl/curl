/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1997 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "setup.h"

#include "splay.h"

/*
 * This macro compares two node keys i and j and returns:
 *
 *  negative value: when i is smaller than j
 *  zero          : when i is equal   to   j
 *  positive when : when i is larger  than j
 */
#define compare(i,j) Curl_splaycomparekeys((i),(j))

/*
 * Splay using the key i (which may or may not be in the tree.) The starting
 * root is t.
 */
struct Curl_tree *Curl_splay(struct timeval i,
                             struct Curl_tree *t)
{
  struct Curl_tree N, *l, *r, *y;
  long comp;

  if(t == NULL)
    return t;
  N.smaller = N.larger = NULL;
  l = r = &N;

  for (;;) {
    comp = compare(i, t->key);
    if(comp < 0) {
      if(t->smaller == NULL)
        break;
      if(compare(i, t->smaller->key) < 0) {
        y = t->smaller;                           /* rotate smaller */
        t->smaller = y->larger;
        y->larger = t;
        t = y;
        if(t->smaller == NULL)
          break;
      }
      r->smaller = t;                               /* link smaller */
      r = t;
      t = t->smaller;
    }
    else if(comp > 0) {
      if(t->larger == NULL)
        break;
      if(compare(i, t->larger->key) > 0) {
        y = t->larger;                          /* rotate larger */
        t->larger = y->smaller;
        y->smaller = t;
        t = y;
        if(t->larger == NULL)
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
struct Curl_tree *Curl_splayinsert(struct timeval i,
                                   struct Curl_tree *t,
                                   struct Curl_tree *node)
{
  static struct timeval KEY_NOTUSED = {-1,-1}; /* key that will *NEVER* appear */

  if(node == NULL)
    return t;

  if(t != NULL) {
    t = Curl_splay(i,t);
    if(compare(i, t->key)==0) {
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

  if(t == NULL) {
    node->smaller = node->larger = NULL;
  }
  else if(compare(i, t->key) < 0) {
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
struct Curl_tree *Curl_splayremove(struct timeval i,
                                   struct Curl_tree *t,
                                   struct Curl_tree **removed)
{
  struct Curl_tree *x;

  *removed = NULL; /* default to no removed */

  if(t==NULL)
    return NULL;

  t = Curl_splay(i,t);
  if(compare(i, t->key) == 0) {               /* found it */

    /* FIRST! Check if there is a list with identical sizes */
    if((x = t->same) != NULL) {
      /* there is, pick one from the list */

      /* 'x' is the new root node */

      x->key = t->key;
      x->larger = t->larger;
      x->smaller = t->smaller;

      *removed = t;
      return x; /* new root */
    }

    if(t->smaller == NULL) {
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
   resulting tree.  best-fit means the node with the given or lower key */
struct Curl_tree *Curl_splaygetbest(struct timeval i,
                                    struct Curl_tree *t,
                                    struct Curl_tree **removed)
{
  struct Curl_tree *x;

  if(!t) {
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

  if(compare(i, t->key) >= 0) {               /* found it */
    /* FIRST! Check if there is a list with identical keys */
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

    if(t->smaller == NULL) {
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
                           struct Curl_tree *removenode,
                           struct Curl_tree **newroot)
{
  static struct timeval KEY_NOTUSED = {-1,-1}; /* key that will *NEVER* appear */
  struct Curl_tree *x;

  if(!t || !removenode)
    return 1;

  if(compare(KEY_NOTUSED, removenode->key) == 0) {
    /* Key set to NOTUSED means it is a subnode within a 'same' linked list
       and thus we can unlink it easily. The 'smaller' link of a subnode
       links to the parent node. */
    if(removenode->smaller == NULL)
      return 3;

    removenode->smaller->same = removenode->same;
    if(removenode->same)
      removenode->same->smaller = removenode->smaller;

    /* Ensures that double-remove gets caught. */
    removenode->smaller = NULL;

    /* voila, we're done! */
    *newroot = t; /* return the same root */
    return 0;
  }

  t = Curl_splay(removenode->key, t);

  /* First make sure that we got the same root node as the one we want
     to remove, as otherwise we might be trying to remove a node that
     isn't actually in the tree.

     We cannot just compare the keys here as a double remove in quick
     succession of a node with key != KEY_NOTUSED && same != NULL
     could return the same key but a different node. */
  if(t != removenode)
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
    if(t->smaller == NULL)
      x = t->larger;
    else {
      x = Curl_splay(removenode->key, t->smaller);
      x->larger = t->larger;
    }
  }

  *newroot = x; /* store new root pointer */

  return 0;
}

#ifdef DEBUGBUILD

void Curl_splayprint(struct Curl_tree * t, int d, char output)
{
  struct Curl_tree *node;
  int i;
  int count;
  if(t == NULL)
    return;

  Curl_splayprint(t->larger, d+1, output);
  for (i=0; i<d; i++)
    if(output)
      fprintf(stderr, "  ");

  if(output) {
#ifdef TEST_SPLAY
    fprintf(stderr, "%ld[%d]", (long)t->key.tv_usec, i);
#else
    fprintf(stderr, "%ld.%ld[%d]", (long)t->key.tv_sec, (long)t->key.tv_usec, i);
#endif
  }

  for(count=0, node = t->same; node; node = node->same, count++)
    ;

  if(output) {
    if(count)
      fprintf(stderr, " [%d more]\n", count);
    else
      fprintf(stderr, "\n");
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
int main(int argc, argv_item_t argv[])
{
  struct Curl_tree *root, *t;
  void *ptrs[MAX];
  int adds=0;
  int rc;

  static const long sizes[]={
    50, 60, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200, 300,
    220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200,
    300, 220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120,
    200, 300, 220, 80, 90};
  int i;
  root = NULL;              /* the empty tree */

  for (i = 0; i < MAX; i++) {
    struct timeval key;
    ptrs[i] = t = malloc(sizeof(struct Curl_tree));

    key.tv_sec = 0;
#ifdef TEST2
    key.tv_usec = sizes[i];
#elif defined(TEST1)
    key.tv_usec = (541*i)%1023;
#elif defined(TEST3)
    key.tv_usec = 100;
#endif

    t->payload = (void *)key.tv_usec; /* for simplicity */
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
    printf("remove pointer %d, payload %ld\n", rem,
           (long)((struct Curl_tree *)ptrs[rem])->payload);
    rc = Curl_splayremovebyaddr(root, (struct Curl_tree *)ptrs[rem], &root);
    if(rc)
      /* failed! */
      printf("remove %d failed!\n", rem);
  }
#endif

  return 0;
}

#endif /* TEST_SPLAY */
