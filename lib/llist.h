#ifndef HEADER_FETCH_LLIST_H
#define HEADER_FETCH_LLIST_H
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
#include <stddef.h>

typedef void (*Fetch_llist_dtor)(void *user, void *elem);

/* none of these struct members should be referenced directly, use the
   dedicated functions */

struct Fetch_llist
{
   struct Fetch_llist_node *_head;
   struct Fetch_llist_node *_tail;
   Fetch_llist_dtor _dtor;
   size_t _size;
#ifdef DEBUGBUILD
   int _init; /* detect API usage mistakes */
#endif
};

struct Fetch_llist_node
{
   struct Fetch_llist *_list; /* the list where this belongs */
   void *_ptr;
   struct Fetch_llist_node *_prev;
   struct Fetch_llist_node *_next;
#ifdef DEBUGBUILD
   int _init; /* detect API usage mistakes */
#endif
};

void Fetch_llist_init(struct Fetch_llist *, Fetch_llist_dtor);
void Fetch_llist_insert_next(struct Fetch_llist *, struct Fetch_llist_node *,
                            const void *, struct Fetch_llist_node *node);
void Fetch_llist_append(struct Fetch_llist *,
                       const void *, struct Fetch_llist_node *node);
void Fetch_node_uremove(struct Fetch_llist_node *, void *);
void Fetch_node_remove(struct Fetch_llist_node *);
void Fetch_llist_destroy(struct Fetch_llist *, void *);

/* Fetch_llist_head() returns the first 'struct Fetch_llist_node *', which
   might be NULL */
struct Fetch_llist_node *Fetch_llist_head(struct Fetch_llist *list);

/* Fetch_llist_tail() returns the last 'struct Fetch_llist_node *', which
   might be NULL */
struct Fetch_llist_node *Fetch_llist_tail(struct Fetch_llist *list);

/* Fetch_llist_count() returns a size_t the number of nodes in the list */
size_t Fetch_llist_count(struct Fetch_llist *list);

/* Fetch_node_elem() returns the custom data from a Fetch_llist_node */
void *Fetch_node_elem(struct Fetch_llist_node *n);

/* Remove the node from the list and return the custom data
 * from a Fetch_llist_node. Will NOT incoke a registered `dtor`. */
void *Fetch_node_take_elem(struct Fetch_llist_node *);

/* Fetch_node_next() returns the next element in a list from a given
   Fetch_llist_node */
struct Fetch_llist_node *Fetch_node_next(struct Fetch_llist_node *n);

/* Fetch_node_prev() returns the previous element in a list from a given
   Fetch_llist_node */
struct Fetch_llist_node *Fetch_node_prev(struct Fetch_llist_node *n);

/* Fetch_node_llist() return the list the node is in or NULL. */
struct Fetch_llist *Fetch_node_llist(struct Fetch_llist_node *n);

#endif /* HEADER_FETCH_LLIST_H */
