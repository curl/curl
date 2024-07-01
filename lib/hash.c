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

#include "curl_setup.h"

#include <curl/curl.h>

#include "hash.h"
#include "llist.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

static void
hash_element_dtor(void *user, void *element)
{
  struct Curl_hash *h = (struct Curl_hash *) user;
  struct Curl_hash_element *e = (struct Curl_hash_element *) element;

  if(e->ptr) {
    if(e->dtor)
      e->dtor(e->key, e->key_len, e->ptr);
    else
      h->dtor(e->ptr);
    e->ptr = NULL;
  }

  e->key_len = 0;

  free(e);
}

/* Initializes a hash structure.
 * Return 1 on error, 0 is fine.
 *
 * @unittest: 1602
 * @unittest: 1603
 */
void
Curl_hash_init(struct Curl_hash *h,
               size_t slots,
               hash_function hfunc,
               comp_function comparator,
               Curl_hash_dtor dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);
  DEBUGASSERT(hfunc);
  DEBUGASSERT(comparator);
  DEBUGASSERT(dtor);

  h->table = NULL;
  h->hash_func = hfunc;
  h->comp_func = comparator;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
}

static struct Curl_hash_element *
mk_hash_element(const void *key, size_t key_len, const void *p,
                Curl_hash_elem_dtor dtor)
{
  /* allocate the struct plus memory after it to store the key */
  struct Curl_hash_element *he = malloc(sizeof(struct Curl_hash_element) +
                                        key_len);
  if(he) {
    /* copy the key */
    memcpy(he->key, key, key_len);
    he->key_len = key_len;
    he->ptr = (void *) p;
    he->dtor = dtor;
  }
  return he;
}

#define FETCH_LIST(x,y,z) &x->table[x->hash_func(y, z, x->slots)]

void *Curl_hash_add2(struct Curl_hash *h, void *key, size_t key_len, void *p,
                     Curl_hash_elem_dtor dtor)
{
  struct Curl_hash_element  *he;
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  if(!h->table) {
    size_t i;
    h->table = malloc(h->slots * sizeof(struct Curl_llist));
    if(!h->table)
      return NULL; /* OOM */
    for(i = 0; i < h->slots; ++i)
      Curl_llist_init(&h->table[i], hash_element_dtor);
  }

  l = FETCH_LIST(h, key, key_len);

  for(le = l->head; le; le = le->next) {
    he = (struct Curl_hash_element *) le->ptr;
    if(h->comp_func(he->key, he->key_len, key, key_len)) {
      Curl_llist_remove(l, le, (void *)h);
      --h->size;
      break;
    }
  }

  he = mk_hash_element(key, key_len, p, dtor);
  if(he) {
    Curl_llist_append(l, he, &he->list);
    ++h->size;
    return p; /* return the new entry */
  }

  return NULL; /* failure */
}

/* Insert the data in the hash. If there already was a match in the hash, that
 * data is replaced. This function also "lazily" allocates the table if
 * needed, as it is not done in the _init function (anymore).
 *
 * @unittest: 1305
 * @unittest: 1602
 * @unittest: 1603
 */
void *
Curl_hash_add(struct Curl_hash *h, void *key, size_t key_len, void *p)
{
  return Curl_hash_add2(h, key, key_len, p, NULL);
}

/* Remove the identified hash entry.
 * Returns non-zero on failure.
 *
 * @unittest: 1603
 */
int Curl_hash_delete(struct Curl_hash *h, void *key, size_t key_len)
{
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  if(h->table) {
    l = FETCH_LIST(h, key, key_len);

    for(le = l->head; le; le = le->next) {
      struct Curl_hash_element *he = le->ptr;
      if(h->comp_func(he->key, he->key_len, key, key_len)) {
        Curl_llist_remove(l, le, (void *) h);
        --h->size;
        return 0;
      }
    }
  }
  return 1;
}

/* Retrieves a hash element.
 *
 * @unittest: 1603
 */
void *
Curl_hash_pick(struct Curl_hash *h, void *key, size_t key_len)
{
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  if(h->table) {
    DEBUGASSERT(h->slots);
    l = FETCH_LIST(h, key, key_len);
    for(le = l->head; le; le = le->next) {
      struct Curl_hash_element *he = le->ptr;
      if(h->comp_func(he->key, he->key_len, key, key_len)) {
        return he->ptr;
      }
    }
  }

  return NULL;
}

/* Destroys all the entries in the given hash and resets its attributes,
 * prepping the given hash for [static|dynamic] deallocation.
 *
 * @unittest: 1305
 * @unittest: 1602
 * @unittest: 1603
 */
void
Curl_hash_destroy(struct Curl_hash *h)
{
  if(h->table) {
    size_t i;
    for(i = 0; i < h->slots; ++i) {
      Curl_llist_destroy(&h->table[i], (void *) h);
    }
    Curl_safefree(h->table);
  }
  h->size = 0;
  h->slots = 0;
}

/* Removes all the entries in the given hash.
 *
 * @unittest: 1602
 */
void
Curl_hash_clean(struct Curl_hash *h)
{
  Curl_hash_clean_with_criterium(h, NULL, NULL);
}

/* Cleans all entries that pass the comp function criteria. */
void
Curl_hash_clean_with_criterium(struct Curl_hash *h, void *user,
                               int (*comp)(void *, void *))
{
  struct Curl_llist_element *le;
  struct Curl_llist_element *lnext;
  struct Curl_llist *list;
  size_t i;

  if(!h || !h->table)
    return;

  for(i = 0; i < h->slots; ++i) {
    list = &h->table[i];
    le = list->head; /* get first list entry */
    while(le) {
      struct Curl_hash_element *he = le->ptr;
      lnext = le->next;
      /* ask the callback function if we shall remove this entry or not */
      if(!comp || comp(user, he->ptr)) {
        Curl_llist_remove(list, le, (void *) h);
        --h->size; /* one less entry in the hash now */
      }
      le = lnext;
    }
  }
}

size_t Curl_hash_str(void *key, size_t key_length, size_t slots_num)
{
  const char *key_str = (const char *) key;
  const char *end = key_str + key_length;
  size_t h = 5381;

  while(key_str < end) {
    size_t j = (size_t)*key_str++;
    h += h << 5;
    h ^= j;
  }

  return (h % slots_num);
}

size_t Curl_str_key_compare(void *k1, size_t key1_len,
                            void *k2, size_t key2_len)
{
  if((key1_len == key2_len) && !memcmp(k1, k2, key1_len))
    return 1;

  return 0;
}

void Curl_hash_start_iterate(struct Curl_hash *hash,
                             struct Curl_hash_iterator *iter)
{
  iter->hash = hash;
  iter->slot_index = 0;
  iter->current_element = NULL;
}

struct Curl_hash_element *
Curl_hash_next_element(struct Curl_hash_iterator *iter)
{
  struct Curl_hash *h = iter->hash;

  if(!h->table)
    return NULL; /* empty hash, nothing to return */

  /* Get the next element in the current list, if any */
  if(iter->current_element)
    iter->current_element = iter->current_element->next;

  /* If we have reached the end of the list, find the next one */
  if(!iter->current_element) {
    size_t i;
    for(i = iter->slot_index; i < h->slots; i++) {
      if(h->table[i].head) {
        iter->current_element = h->table[i].head;
        iter->slot_index = i + 1;
        break;
      }
    }
  }

  if(iter->current_element) {
    struct Curl_hash_element *he = iter->current_element->ptr;
    return he;
  }
  return NULL;
}

#if 0 /* useful function for debugging hashes and their contents */
void Curl_hash_print(struct Curl_hash *h,
                     void (*func)(void *))
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;
  size_t last_index = ~0;

  if(!h)
    return;

  fprintf(stderr, "=Hash dump=\n");

  Curl_hash_start_iterate(h, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(iter.slot_index != last_index) {
      fprintf(stderr, "index %d:", iter.slot_index);
      if(last_index != ~0) {
        fprintf(stderr, "\n");
      }
      last_index = iter.slot_index;
    }

    if(func)
      func(he->ptr);
    else
      fprintf(stderr, " [%p]", (void *)he->ptr);

    he = Curl_hash_next_element(&iter);
  }
  fprintf(stderr, "\n");
}
#endif

void Curl_hash_offt_init(struct Curl_hash *h,
                         size_t slots,
                         Curl_hash_dtor dtor)
{
  Curl_hash_init(h, slots, Curl_hash_str, Curl_str_key_compare, dtor);
}

void *Curl_hash_offt_set(struct Curl_hash *h, curl_off_t id, void *elem)
{
  return Curl_hash_add(h, &id, sizeof(id), elem);
}

int Curl_hash_offt_remove(struct Curl_hash *h, curl_off_t id)
{
  return Curl_hash_delete(h, &id, sizeof(id));
}

void *Curl_hash_offt_get(struct Curl_hash *h, curl_off_t id)
{
  return Curl_hash_pick(h, &id, sizeof(id));
}
