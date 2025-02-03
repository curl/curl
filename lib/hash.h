#ifndef HEADER_FETCH_HASH_H
#define HEADER_FETCH_HASH_H
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

#include "llist.h"

/* Hash function prototype */
typedef size_t (*hash_function)(void *key,
                                size_t key_length,
                                size_t slots_num);

/*
   Comparator function prototype. Compares two keys.
*/
typedef size_t (*comp_function)(void *key1,
                                size_t key1_len,
                                void *key2,
                                size_t key2_len);

typedef void (*Fetch_hash_dtor)(void *);

struct Fetch_hash
{
  struct Fetch_llist *table;

  /* Hash function to be used for this hash table */
  hash_function hash_func;

  /* Comparator function to compare keys */
  comp_function comp_func;
  Fetch_hash_dtor dtor;
  size_t slots;
  size_t size;
#ifdef DEBUGBUILD
  int init;
#endif
};

typedef void (*Fetch_hash_elem_dtor)(void *key, size_t key_len, void *p);

struct Fetch_hash_element
{
  struct Fetch_llist_node list;
  void *ptr;
  Fetch_hash_elem_dtor dtor;
  size_t key_len;
#ifdef DEBUGBUILD
  int init;
#endif
  char key[1]; /* allocated memory following the struct */
};

struct Fetch_hash_iterator
{
  struct Fetch_hash *hash;
  size_t slot_index;
  struct Fetch_llist_node *current_element;
#ifdef DEBUGBUILD
  int init;
#endif
};

void Fetch_hash_init(struct Fetch_hash *h,
                    size_t slots,
                    hash_function hfunc,
                    comp_function comparator,
                    Fetch_hash_dtor dtor);

void *Fetch_hash_add(struct Fetch_hash *h, void *key, size_t key_len, void *p);
void *Fetch_hash_add2(struct Fetch_hash *h, void *key, size_t key_len, void *p,
                     Fetch_hash_elem_dtor dtor);
int Fetch_hash_delete(struct Fetch_hash *h, void *key, size_t key_len);
void *Fetch_hash_pick(struct Fetch_hash *, void *key, size_t key_len);

void Fetch_hash_destroy(struct Fetch_hash *h);
size_t Fetch_hash_count(struct Fetch_hash *h);
void Fetch_hash_clean(struct Fetch_hash *h);
void Fetch_hash_clean_with_criterium(struct Fetch_hash *h, void *user,
                                    int (*comp)(void *, void *));
size_t Fetch_hash_str(void *key, size_t key_length, size_t slots_num);
size_t Fetch_str_key_compare(void *k1, size_t key1_len, void *k2,
                            size_t key2_len);
void Fetch_hash_start_iterate(struct Fetch_hash *hash,
                             struct Fetch_hash_iterator *iter);
struct Fetch_hash_element *
Fetch_hash_next_element(struct Fetch_hash_iterator *iter);

void Fetch_hash_print(struct Fetch_hash *h,
                     void (*func)(void *));

/* Hash for `fetch_off_t` as key */
void Fetch_hash_offt_init(struct Fetch_hash *h, size_t slots,
                         Fetch_hash_dtor dtor);

void *Fetch_hash_offt_set(struct Fetch_hash *h, fetch_off_t id, void *elem);
int Fetch_hash_offt_remove(struct Fetch_hash *h, fetch_off_t id);
void *Fetch_hash_offt_get(struct Fetch_hash *h, fetch_off_t id);

#endif /* HEADER_FETCH_HASH_H */
