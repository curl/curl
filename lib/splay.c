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
    else {
      break;
    }
  }
  l->larger = r->smaller = NULL;

  l->larger = t->smaller;                                /* assemble */
  r->smaller = t->larger;
  t->smaller = N.larger;
  t->larger = N.smaller;

  return t;
}

/* Insert key i into the tree t.  Return a pointer to the resulting tree or
   NULL if something went wrong. */
struct Curl_tree *Curl_splayinsert(int i, struct Curl_tree *t,
                                   struct Curl_tree *area)
{
  if (area == NULL)
    return t;

  if (t != NULL) {
    t = Curl_splay(i,t);
    if (compare(i, t->key)==0) {
      /* it already exists one of this size */

      area->same = t;
      area->key = i;
      area->smaller = t->smaller;
      area->larger = t->larger;

      t->smaller = area;
      t->key = KEY_NOTUSED;

      return area; /* new root node */
    }
  }

  if (t == NULL) {
    area->smaller = area->larger = NULL;
  }
  else if (compare(i, t->key) < 0) {
    area->smaller = t->smaller;
    area->larger = t;
    t->smaller = NULL;

  }
  else {
    area->larger = t->larger;
    area->smaller = t;
    t->larger = NULL;
  }
  area->key = i;

  area->same = NULL; /* no identical node (yet) */
  return area;
}

/* Deletes 'i' from the tree if it's there (with an exact match). Returns a
   pointer to the resulting tree.  */
struct Curl_tree *Curl_splayremove(int i, struct Curl_tree *t,
                                   struct Curl_tree **removed)
{
  struct Curl_tree *x;

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
  else {
    *removed = NULL; /* no match */
    return t;                         /* It wasn't there */
  }
}

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


/* Deletes the node we point out from the tree if it's there. Return a pointer
   to the resulting tree.  */
struct Curl_tree *Curl_splayremovebyaddr(struct Curl_tree *t,
                                         struct Curl_tree *remove)
{
  struct Curl_tree *x;

  if (!t || !remove)
    return NULL;

  if(KEY_NOTUSED == remove->key) {
    /* just unlink ourselves nice and quickly: */
    remove->smaller->same = remove->same;
    if(remove->same)
      remove->same->smaller = remove->smaller;
    /* voila, we're done! */
    return t;
  }

  t = Curl_splay(remove->key, t);

  /* Check if there is a list with identical sizes */

  x = t->same;
  if(x) {
    /* 'x' is the new root node */

    x->key = t->key;
    x->larger = t->larger;
    x->smaller = t->smaller;

    return x; /* new root */
  }

  /* Remove the actualy root node: */
  if (t->smaller == NULL)
    x = t->larger;
  else {
    x = Curl_splay(remove->key, t->smaller);
    x->larger = t->larger;
  }

  return x;
}

#ifdef CURLDEBUG

int Curl_splayprint(struct Curl_tree * t, int d, char output)
{
  int distance=0;
  struct Curl_tree *node;
  int i;
  if (t == NULL)
    return 0;
  distance += Curl_splayprint(t->larger, d+1, output);
  for (i=0; i<d; i++)
    if(output)
      printf("  ");

  if(output) {
    printf("%d[%d]", t->key, i);
  }

  for(node = t->same; node; node = node->same) {
    distance += i; /* this has the same "virtual" distance */

    if(output)
      printf(" [+]");
  }
  if(output)
    puts("");

  distance += i;

  distance += Curl_splayprint(t->smaller, d+1, output);

  return distance;
}
#endif

#ifdef TEST_SPLAY

/*#define TEST2 */
#define MAX 50
#define OUTPUT 0 /* 1 enables, 0 disables */

/* A sample use of these functions.  Start with the empty tree, insert some
   stuff into it, and then delete it */
int main(int argc, char **argv)
{
  struct Curl_tree *root, *t;
  void *ptrs[MAX];

  long sizes[]={
    50, 60, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200, 300,
    220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120, 200,
    300, 220, 80, 90, 50, 100, 60, 200, 120, 300, 400, 200, 256, 122, 60, 120,
    200, 300, 220, 80, 90};
  int i;
  root = NULL;              /* the empty tree */

  for (i = 0; i < MAX; i++) {
    ptrs[i] = t = (struct Curl_tree *)malloc(sizeof(struct Curl_tree));
    if(!t) {
      puts("out of memory!");
      return 0;
    }
#ifdef TEST2
    root = Curl_splayinsert(sizes[i], root, t);
#else
    root = Curl_splayinsert((541*i)&1023, root, t);
#endif
  }

#if 0
  puts("Result:");
  printtree(root, 0, 1);
#endif

#if 1
  for (i=0; root; i+=30) {
    Curl_splayprint(root, 0, 1);
    do {
      root = Curl_splaygetbest(i, root, &t);
      if(t)
        printf("bestfit %d became %d\n", i, t->key);
      else
        printf("bestfit %d failed!\n", i);
    } while(t && root);
  }
#endif
#if 0
  for (i = 0; i < MAX; i++) {
    printf("remove pointer %d size %d\n", i, sizes[i]);
    root = removebyaddr(root, (struct Curl_tree *)ptrs[i]);
    Curl_splayprint(root, 0, 1);
  }
#endif

#if 0
#ifdef WEIGHT
  for (i = -1; i<=root->weight; i++) {
    t = find_rank(i, root);
    if (t == NULL) {
      printf("could not find a node of rank %d.\n", i);
    } else {
      printf("%d is of rank %d\n", t->key, i);
    }
  }
#endif
#endif

#if 0
#ifdef TEST2
  for (i = 0; i < MAX; i++) {
    printf("remove size %d\n", sizes[i]);
    root = Curl_splayremove(sizes[i], root, &t);
    free(t);
    Curl_splayprint(root, 0, 1);
  }
#endif
#endif
  return 0;
}

#endif /* TEST_SPLAY */
