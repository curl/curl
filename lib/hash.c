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

/* random patterns for API verification */
#ifdef DEBUGBUILD
#define HASHINIT 0x7017e781
#define ITERINIT 0x5FEDCBA9
#endif


#if 0 /* useful function for debugging hashes and their contents */
void Curl_hash_print(struct Curl_hash *h,
                     void (*func)(void *))
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;
  size_t last_index = UINT_MAX;

  if(!h)
    return;

  fprintf(stderr, "=Hash dump=\n");

  Curl_hash_start_iterate(h, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(iter.slot_index != last_index) {
      fprintf(stderr, "index %d:", (int)iter.slot_index);
      if(last_index != UINT_MAX) {
        fprintf(stderr, "\n");
      }
      last_index = iter.slot_index;
    }

    if(func)
      func(he->ptr);
    else
      fprintf(stderr, " [key=%.*s, he=%p, ptr=%p]",
              (int)he->key_len, (char *)he->key,
              (void *)he, (void *)he->ptr);

    he = Curl_hash_next_element(&iter);
  }
  fprintf(stderr, "\n");
}
#endif

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
#ifdef DEBUGBUILD
  h->init = HASHINIT;
#endif
}

static struct Curl_hash_element *
hash_elem_create(const void *key, size_t key_len, const void *p,
                 Curl_hash_elem_dtor dtor)
{
  struct Curl_hash_element *he;

  /* allocate the struct plus memory after it to store the key */
  he = malloc(sizeof(struct Curl_hash_element) + key_len);
  if(he) {
    he->next = NULL;
    /* copy the key */
    memcpy(he->key, key, key_len);
    he->key_len = key_len;
    he->ptr = CURL_UNCONST(p);
    he->dtor = dtor;
  }
  return he;
}

static void hash_elem_clear_ptr(struct Curl_hash *h,
                                struct Curl_hash_element *he)
{
  DEBUGASSERT(h);
  DEBUGASSERT(he);
  if(he->ptr) {
    if(he->dtor)
      he->dtor(he->key, he->key_len, he->ptr);
    else
      h->dtor(he->ptr);
    he->ptr = NULL;
  }
}

static void hash_elem_destroy(struct Curl_hash *h,
                              struct Curl_hash_element *he)
{
  hash_elem_clear_ptr(h, he);
  free(he);
}

static void hash_elem_unlink(struct Curl_hash *h,
                             struct Curl_hash_element **he_anchor,
                             struct Curl_hash_element *he)
{
  *he_anchor = he->next;
  --h->size;
}

static void hash_elem_link(struct Curl_hash *h,
                           struct Curl_hash_element **he_anchor,
                           struct Curl_hash_element *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

#define CURL_HASH_SLOT(x,y,z)      x->table[x->hash_func(y, z, x->slots)]
#define CURL_HASH_SLOT_ADDR(x,y,z) &CURL_HASH_SLOT(x,y,z)

void *Curl_hash_add2(struct Curl_hash *h, void *key, size_t key_len, void *p,
                     Curl_hash_elem_dtor dtor)
{
  struct Curl_hash_element *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == HASHINIT);
  if(!h->table) {
    h->table = calloc(h->slots, sizeof(struct Curl_hash_element *));
    if(!h->table)
      return NULL; /* OOM */
  }

  slot = CURL_HASH_SLOT_ADDR(h, key, key_len);
  for(he = *slot; he; he = he->next) {
    if(h->comp_func(he->key, he->key_len, key, key_len)) {
      /* existing key entry, overwrite by clearing old pointer */
      hash_elem_clear_ptr(h, he);
      he->ptr = (void *)p;
      he->dtor = dtor;
      return p;
    }
  }

  he = hash_elem_create(key, key_len, p, dtor);
  if(!he)
    return NULL; /* OOM */

  hash_elem_link(h, slot, he);
  return p; /* return the new entry */
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
  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == HASHINIT);
  if(h->table) {
    struct Curl_hash_element *he, **he_anchor;

    he_anchor = CURL_HASH_SLOT_ADDR(h, key, key_len);
    while(*he_anchor) {
      he = *he_anchor;
      if(h->comp_func(he->key, he->key_len, key, key_len)) {
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
        return 0;
      }
      he_anchor = &he->next;
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
  DEBUGASSERT(h);
  DEBUGASSERT(h->init == HASHINIT);
  if(h->table) {
    struct Curl_hash_element *he;
    DEBUGASSERT(h->slots);
    he = CURL_HASH_SLOT(h, key, key_len);
    while(he) {
      if(h->comp_func(he->key, he->key_len, key, key_len)) {
        return he->ptr;
      }
      he = he->next;
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
  DEBUGASSERT(h->init == HASHINIT);
  if(h->table) {
    Curl_hash_clean(h);
    Curl_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

/* Removes all the entries in the given hash.
 *
 * @unittest: 1602
 */
void Curl_hash_clean(struct Curl_hash *h)
{
  if(h && h->table) {
    struct Curl_hash_element *he, **he_anchor;
    size_t i;
    DEBUGASSERT(h->init == HASHINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
      }
    }
  }
}

size_t Curl_hash_count(struct Curl_hash *h)
{
  DEBUGASSERT(h->init == HASHINIT);
  return h->size;
}

/* Cleans all entries that pass the comp function criteria. */
void
Curl_hash_clean_with_criterium(struct Curl_hash *h, void *user,
                               int (*comp)(void *, void *))
{
  size_t i;

  if(!h || !h->table)
    return;

  DEBUGASSERT(h->init == HASHINIT);
  for(i = 0; i < h->slots; ++i) {
    struct Curl_hash_element *he, **he_anchor = &h->table[i];
    while(*he_anchor) {
      /* ask the callback function if we shall remove this entry or not */
      if(!comp || comp(user, (*he_anchor)->ptr)) {
        he = *he_anchor;
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
      }
      else
        he_anchor = &(*he_anchor)->next;
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

size_t curlx_str_key_compare(void *k1, size_t key1_len,
                            void *k2, size_t key2_len)
{
  if((key1_len == key2_len) && !memcmp(k1, k2, key1_len))
    return 1;

  return 0;
}

void Curl_hash_start_iterate(struct Curl_hash *hash,
                             struct Curl_hash_iterator *iter)
{
  DEBUGASSERT(hash->init == HASHINIT);
  iter->hash = hash;
  iter->slot_index = 0;
  iter->current = NULL;
#ifdef DEBUGBUILD
  iter->init = ITERINIT;
#endif
}

struct Curl_hash_element *
Curl_hash_next_element(struct Curl_hash_iterator *iter)
{
  struct Curl_hash *h;
  DEBUGASSERT(iter->init == ITERINIT);
  h = iter->hash;
  if(!h->table)
    return NULL; /* empty hash, nothing to return */

  /* Get the next element in the current list, if any */
  if(iter->current)
    iter->current = iter->current->next;

  /* If we have reached the end of the list, find the next one */
  if(!iter->current) {
    size_t i;
    for(i = iter->slot_index; i < h->slots; i++) {
      if(h->table[i]) {
        iter->current = h->table[i];
        iter->slot_index = i + 1;
        break;
      }
    }
  }

  return iter->current;
}
