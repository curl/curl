#ifndef HEADER_FETCH_SPLAY_H
#define HEADER_FETCH_SPLAY_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetch_setup.h"
#include "timeval.h"

/* only use function calls to access this struct */
struct Fetch_tree
{
  struct Fetch_tree *smaller; /* smaller node */
  struct Fetch_tree *larger;  /* larger node */
  struct Fetch_tree *samen;   /* points to the next node with identical key */
  struct Fetch_tree *samep;   /* points to the prev node with identical key */
  struct fetchtime key;      /* this node's "sort" key */
  void *ptr;                 /* data the splay code does not care about */
};

struct Fetch_tree *Fetch_splay(struct fetchtime i,
                             struct Fetch_tree *t);

struct Fetch_tree *Fetch_splayinsert(struct fetchtime key,
                                   struct Fetch_tree *t,
                                   struct Fetch_tree *newnode);

struct Fetch_tree *Fetch_splaygetbest(struct fetchtime key,
                                    struct Fetch_tree *t,
                                    struct Fetch_tree **removed);

int Fetch_splayremove(struct Fetch_tree *t,
                     struct Fetch_tree *removenode,
                     struct Fetch_tree **newroot);

/* set and get the custom payload for this tree node */
void Fetch_splayset(struct Fetch_tree *node, void *payload);
void *Fetch_splayget(struct Fetch_tree *node);

#endif /* HEADER_FETCH_SPLAY_H */
