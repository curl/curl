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

#include "uint-hash.h"

/* random patterns for API verification */
#ifdef DEBUGBUILD
#define CURL_UINT32_HASHINIT 0x7117e779
#endif

static uint32_t uint32_hash_hash(uint32_t id, uint32_t slots)
{
  return (id % slots);
}

struct uint_hash_entry {
  struct uint_hash_entry *next;
  void *value;
  uint32_t id;
};

void Curl_uint32_hash_init(struct uint_hash *h,
                           uint32_t slots,
                           Curl_uint32_hash_dtor *dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);

  h->table = NULL;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
#ifdef DEBUGBUILD
  h->init = CURL_UINT32_HASHINIT;
#endif
}

static struct uint_hash_entry *uint32_hash_mk_entry(uint32_t id, void *value)
{
  struct uint_hash_entry *e;

  /* allocate the struct for the hash entry */
  e = curlx_malloc(sizeof(*e));
  if(e) {
    e->id = id;
    e->next = NULL;
    e->value = value;
  }
  return e;
}

static void uint32_hash_entry_clear(struct uint_hash *h,
                                    struct uint_hash_entry *e)
{
  DEBUGASSERT(h);
  DEBUGASSERT(e);
  if(e->value) {
    if(h->dtor)
      h->dtor(e->id, e->value);
    e->value = NULL;
  }
}

static void uint32_hash_entry_destroy(struct uint_hash *h,
                                      struct uint_hash_entry *e)
{
  uint32_hash_entry_clear(h, e);
  curlx_free(e);
}

static void uint32_hash_entry_unlink(struct uint_hash *h,
                                     struct uint_hash_entry **he_anchor,
                                     struct uint_hash_entry *he)
{
  *he_anchor = he->next;
  --h->size;
}

static void uint32_hash_elem_link(struct uint_hash *h,
                                  struct uint_hash_entry **he_anchor,
                                  struct uint_hash_entry *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

#define CURL_UINT32_HASH_SLOT(h, id) h->table[uint32_hash_hash(id, h->slots)]
#define CURL_UINT32_HASH_SLOT_ADDR(h, id) &CURL_UINT32_HASH_SLOT(h, id)

bool Curl_uint32_hash_set(struct uint_hash *h, uint32_t id, void *value)
{
  struct uint_hash_entry *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
  if(!h->table) {
    h->table = curlx_calloc(h->slots, sizeof(*he));
    if(!h->table)
      return FALSE; /* OOM */
  }

  slot = CURL_UINT32_HASH_SLOT_ADDR(h, id);
  for(he = *slot; he; he = he->next) {
    if(he->id == id) {
      /* existing key entry, overwrite by clearing old pointer */
      uint32_hash_entry_clear(h, he);
      he->value = value;
      return TRUE;
    }
  }

  he = uint32_hash_mk_entry(id, value);
  if(!he)
    return FALSE; /* OOM */

  uint32_hash_elem_link(h, slot, he);
  return TRUE;
}

bool Curl_uint32_hash_remove(struct uint_hash *h, uint32_t id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
  if(h->table) {
    struct uint_hash_entry *he, **he_anchor;

    he_anchor = CURL_UINT32_HASH_SLOT_ADDR(h, id);
    while(*he_anchor) {
      he = *he_anchor;
      if(id == he->id) {
        uint32_hash_entry_unlink(h, he_anchor, he);
        uint32_hash_entry_destroy(h, he);
        return TRUE;
      }
      he_anchor = &he->next;
    }
  }
  return FALSE;
}

void *Curl_uint32_hash_get(struct uint_hash *h, uint32_t id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
  if(h->table) {
    struct uint_hash_entry *he;
    DEBUGASSERT(h->slots);
    he = CURL_UINT32_HASH_SLOT(h, id);
    while(he) {
      if(id == he->id) {
        return he->value;
      }
      he = he->next;
    }
  }
  return NULL;
}

static void uint_hash_clear(struct uint_hash *h)
{
  if(h && h->table) {
    struct uint_hash_entry *he, **he_anchor;
    size_t i;
    DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        uint32_hash_entry_unlink(h, he_anchor, he);
        uint32_hash_entry_destroy(h, he);
      }
    }
  }
}

#ifdef UNITTESTS
UNITTEST void Curl_uint32_hash_clear(struct uint_hash *h)
{
  uint_hash_clear(h);
}
#endif

void Curl_uint32_hash_destroy(struct uint_hash *h)
{
  DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
  if(h->table) {
    uint_hash_clear(h);
    Curl_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

uint32_t Curl_uint32_hash_count(struct uint_hash *h)
{
  DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
  return h->size;
}

void Curl_uint32_hash_visit(struct uint_hash *h,
                            Curl_uint32_hash_visit_cb *cb,
                            void *user_data)
{
  if(h && h->table && cb) {
    struct uint_hash_entry *he;
    size_t i;
    DEBUGASSERT(h->init == CURL_UINT32_HASHINIT);
    for(i = 0; i < h->slots; ++i) {
      for(he = h->table[i]; he; he = he->next) {
        if(!cb(he->id, he->value, user_data))
          return;
      }
    }
  }
}
