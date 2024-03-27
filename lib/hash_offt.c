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

#include "llist.h"
#include "hash_offt.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

static unsigned int offt_hash(curl_off_t id, unsigned int bits)
{
  static unsigned int knuth = 2654435769;
  /* assume that the lower 32 bits are evenly distributed */
  unsigned int n = (unsigned int)(id & 0xffffffff);
  return ((n * knuth) >> (32 - bits));
}

static void offt_hash_entry_dtor(void *user_data, void *entry)
{
  struct Curl_hash_offt *h = (struct Curl_hash_offt *)user_data;
  struct Curl_hash_offt_entry *e = (struct Curl_hash_offt_entry *)entry;

  if(e->elem) {
    h->dtor(e->elem, h->dtor_user_data);
    e->elem = NULL;
  }
  e->id = 0;
  free(e);
}

void Curl_hash_offt_init(struct Curl_hash_offt *h,
                         unsigned char bits,
                         Curl_hash_offt_dtor *dtor,
                         void *dtor_user_data)
{
  DEBUGASSERT(h);
  DEBUGASSERT(bits);
  DEBUGASSERT(bits <= 15); /* max 32k slots */
  DEBUGASSERT(dtor);

  h->table = NULL;
  h->dtor = dtor;
  h->dtor_user_data = dtor_user_data;
  h->size = 0;
  h->bits = bits;
  h->slots = (unsigned int)(1 << bits);
}

static struct Curl_hash_offt_entry *
mk_hash_entry(curl_off_t id, const void *elem)
{
  struct Curl_hash_offt_entry *he;
  he = malloc(sizeof(struct Curl_hash_offt_entry));
  if(he) {
    he->id = id;
    he->elem = (void *)elem;
  }
  return he;
}

#define FETCH_LIST(x,y) &(x)->table[offt_hash(y, (x)->bits)]

void *Curl_hash_offt_set(struct Curl_hash_offt *h, curl_off_t id, void *elem)
{
  struct Curl_hash_offt_entry  *he;
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  if(!h->table) {
    unsigned int i;
    h->table = malloc(h->slots * sizeof(struct Curl_llist));
    if(!h->table)
      return NULL; /* OOM */
    for(i = 0; i < h->slots; ++i)
      Curl_llist_init(&h->table[i], offt_hash_entry_dtor);
  }

  l = FETCH_LIST(h, id);

  for(le = l->head; le; le = le->next) {
    he = (struct Curl_hash_offt_entry *) le->ptr;
    if(id == he->id) {
      Curl_llist_remove(l, le, (void *)h);
      --h->size;
      break;
    }
  }

  he = mk_hash_entry(id, elem);
  if(he) {
    Curl_llist_insert_next(l, l->tail, he, &he->list);
    ++h->size;
    return elem; /* return the new entry */
  }

  return NULL; /* failure */
}

int Curl_hash_offt_remove(struct Curl_hash_offt *h, curl_off_t id)
{
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  if(h->table) {
    l = FETCH_LIST(h, id);

    for(le = l->head; le; le = le->next) {
      struct Curl_hash_offt_entry *he = le->ptr;
      if(id == he->id) {
        Curl_llist_remove(l, le, (void *) h);
        --h->size;
        return 0;
      }
    }
  }
  return 1;
}

void *Curl_hash_offt_get(struct Curl_hash_offt *h, curl_off_t id)
{
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  if(h->table) {
    DEBUGASSERT(h->slots);
    l = FETCH_LIST(h, id);
    for(le = l->head; le; le = le->next) {
      struct Curl_hash_offt_entry *he = le->ptr;
      if(id == he->id) {
        return he->elem;
      }
    }
  }

  return NULL;
}

void Curl_hash_offt_reset(struct Curl_hash_offt *h)
{
  if(h->table) {
    unsigned int i;
    for(i = 0; i < h->slots; ++i) {
      Curl_llist_destroy(&h->table[i], (void *) h);
    }
  }
  h->size = 0;
}

void Curl_hash_offt_destroy(struct Curl_hash_offt *h)
{
  Curl_hash_offt_reset(h);
  Curl_safefree(h->table);
  h->slots = 0;
}

struct Curl_hash_offt_entry *
Curl_hash_offt_iter_first(struct Curl_hash_offt *hash,
                          struct Curl_hash_offt_iterator *iter)
{
  iter->hash = hash;
  iter->slot_index = 0;
  iter->current_element = NULL;
  return Curl_hash_offt_iter_next(iter);
}

struct Curl_hash_offt_entry *
Curl_hash_offt_iter_next(struct Curl_hash_offt_iterator *iter)
{
  struct Curl_hash_offt *h = iter->hash;

  if(!h->table)
    return NULL; /* empty hash, nothing to return */

  /* Get the next element in the current list, if any */
  if(iter->current_element)
    iter->current_element = iter->current_element->next;

  /* If we have reached the end of the list, find the next one */
  if(!iter->current_element) {
    unsigned int i;
    for(i = iter->slot_index; i < h->slots; i++) {
      if(h->table[i].head) {
        iter->current_element = h->table[i].head;
        iter->slot_index = i + 1;
        break;
      }
    }
  }

  if(iter->current_element) {
    struct Curl_hash_offt_entry *he = iter->current_element->ptr;
    return he;
  }
  return NULL;
}
