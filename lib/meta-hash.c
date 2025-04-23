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

#include "dynbuf.h"
#include "meta-hash.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

/* random patterns for API verification */
#ifdef DEBUGBUILD
#define CURL_METAHASHINIT 0x71177117
#endif

static bool meta_key_same(const struct meta_key *k1,
                          const struct meta_key *k2)
{
  return (k1 == k2) ||
         ((k1->id_len == k2->id_len) && !strcmp(k1->id, k2->id));
}

static unsigned int meta_hash_hash(const struct meta_key *key,
                                   unsigned int slots)
{
  const char *key_str = key->id;
  const char *end = key_str + key->id_len;
  size_t h = 5381;

  while(key_str < end) {
    size_t j = (size_t)*key_str++;
    h += h << 5;
    h ^= j;
  }

  return (h % slots);
}

struct meta_hash_entry {
  struct meta_hash_entry *next;
  const struct meta_key *key;
  void *value;
};

void Curl_meta_hash_init(struct meta_hash *h, unsigned int slots)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);

  h->table = NULL;
  h->size = 0;
  h->slots = slots;
#ifdef DEBUGBUILD
  h->init = CURL_METAHASHINIT;
#endif
}

static struct meta_hash_entry *
meta_hash_mk_entry(const struct meta_key *key, void *value)
{
  struct meta_hash_entry *e = malloc(sizeof(*e));
  if(e) {
    e->next = NULL;
    e->key = key;
    e->value = value;
  }
  return e;
}

static void meta_hash_entry_clear(struct meta_hash_entry *e)
{
  DEBUGASSERT(e->key);
  if(e->key && e->value) {
    if(e->key->dtor)
      e->key->dtor(e->key, e->value);
    e->value = NULL;
  }
}

static void meta_hash_entry_destroy(struct meta_hash_entry *e)
{
  meta_hash_entry_clear(e);
  free(e);
}

static void meta_hash_entry_unlink(struct meta_hash *h,
                                   struct meta_hash_entry **he_anchor,
                                   struct meta_hash_entry *he)
{
  *he_anchor = he->next;
  --h->size;
}

static void meta_hash_elem_link(struct meta_hash *h,
                                struct meta_hash_entry **he_anchor,
                                struct meta_hash_entry *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

#define CURL_META_HASH_SLOT(h,key)  h->table[meta_hash_hash(key, h->slots)]
#define CURL_META_HASH_SLOT_ADDR(h,key) &CURL_META_HASH_SLOT(h,key)

bool Curl_meta_hash_set(struct meta_hash *h,
                        const struct meta_key *key, void *value)
{
  struct meta_hash_entry *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_METAHASHINIT);
  if(!h->table) {
    h->table = calloc(h->slots, sizeof(*he));
    if(!h->table)
      return FALSE; /* OOM */
  }

  slot = CURL_META_HASH_SLOT_ADDR(h, key);
  for(he = *slot; he; he = he->next) {
    if(meta_key_same(key, he->key)) {
      /* existing key entry, overwrite by clearing old pointer */
      meta_hash_entry_clear(he);
      he->value = value;
      return TRUE;
    }
  }

  he = meta_hash_mk_entry(key, value);
  if(!he)
    return FALSE; /* OOM */

  meta_hash_elem_link(h, slot, he);
  return TRUE;
}

bool Curl_meta_hash_remove(struct meta_hash *h, const struct meta_key *key)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_METAHASHINIT);
  if(h->table) {
    struct meta_hash_entry *he, **he_anchor;

    he_anchor = CURL_META_HASH_SLOT_ADDR(h, key);
    while(*he_anchor) {
      he = *he_anchor;
      if(meta_key_same(key, he->key)) {
        meta_hash_entry_unlink(h, he_anchor, he);
        meta_hash_entry_destroy(he);
        return TRUE;
      }
      he_anchor = &he->next;
    }
  }
  return FALSE;
}

void *Curl_meta_hash_get(struct meta_hash *h, const struct meta_key *key)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->init == CURL_METAHASHINIT);
  if(h->table) {
    struct meta_hash_entry *he;
    DEBUGASSERT(h->slots);
    he = CURL_META_HASH_SLOT(h, key);
    while(he) {
      if(meta_key_same(key, he->key)) {
        return he->value;
      }
      he = he->next;
    }
  }
  return NULL;
}

static void meta_hash_clear(struct meta_hash *h)
{
  if(h && h->table) {
    struct meta_hash_entry *he, **he_anchor;
    size_t i;
    DEBUGASSERT(h->init == CURL_METAHASHINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        meta_hash_entry_unlink(h, he_anchor, he);
        meta_hash_entry_destroy(he);
      }
    }
  }
}

void Curl_meta_hash_clear(struct meta_hash *h)
{
  meta_hash_clear(h);
}

void Curl_meta_hash_destroy(struct meta_hash *h)
{
  DEBUGASSERT(h->init == CURL_METAHASHINIT);
  if(h->table) {
    meta_hash_clear(h);
    Curl_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

void Curl_meta_str_dtor(const struct meta_key *key, void *value)
{
  (void)key;
  DEBUGASSERT(key->type == CURL_META_STR);
  free(value);
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
CURLcode Curl_meta_str_print(struct dynbuf *buf,
                             const struct meta_key *key, void *value)
{
  (void)key;
  return Curl_dyn_add(buf, (const char *)value);
}
#endif
