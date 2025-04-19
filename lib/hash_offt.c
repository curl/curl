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

#include "hash_offt.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

/* random patterns for API verification */
#ifdef DEBUGBUILD
#define CURL_HASHOFFTINIT 0x7117e781
#endif

static size_t hash_offt_hash(curl_off_t id, size_t slots)
{
  return (size_t)((id >= 0) ? (id % slots) : (-id % slots));
}

struct Curl_hash_offt_entry {
  curl_off_t id;
  struct Curl_hash_offt_entry *next;
  void   *value;
};

void Curl_hash_offt_init(struct Curl_hash_offt *h,
                         size_t slots,
                         Curl_hash_offt_dtor *dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);

  h->table = NULL;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
#ifdef DEBUGBUILD
  h->init = CURL_HASHOFFTINIT;
#endif
}

static struct Curl_hash_offt_entry *
hash_offt_mk_entry(curl_off_t id, void *value)
{
  struct Curl_hash_offt_entry *e;

  /* allocate the struct for the hash entry */
  e = malloc(sizeof(*e));
  if(e) {
    e->id = id;
    e->next = NULL;
    e->value = value;
  }
  return e;
}

static void hash_offt_entry_clear(struct Curl_hash_offt *h,
                                  struct Curl_hash_offt_entry *e)
{
  DEBUGASSERT(h);
  DEBUGASSERT(e);
  if(e->value) {
    if(h->dtor)
      h->dtor(e->id, e->value);
    e->value = NULL;
  }
}

static void hash_offt_entry_destroy(struct Curl_hash_offt *h,
                                    struct Curl_hash_offt_entry *e)
{
  hash_offt_entry_clear(h, e);
  free(e);
}

static void hash_offt_entry_unlink(struct Curl_hash_offt *h,
                                   struct Curl_hash_offt_entry **he_anchor,
                                   struct Curl_hash_offt_entry *he)
{
  *he_anchor = he->next;
  --h->size;
}

static void hash_offtr_elem_link(struct Curl_hash_offt *h,
                                 struct Curl_hash_offt_entry **he_anchor,
                                 struct Curl_hash_offt_entry *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

#define CURL_HASH_OFFT_SLOT(h,id)  h->table[hash_offt_hash(id, h->slots)]
#define CURL_HASH_OFFT_SLOT_ADDR(h,id) &CURL_HASH_OFFT_SLOT(h,id)

bool Curl_hash_offt_set(struct Curl_hash_offt *h, curl_off_t id, void *value)
{
  struct Curl_hash_offt_entry *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
  if(!h->table) {
    h->table = calloc(h->slots, sizeof(*he));
    if(!h->table)
      return FALSE; /* OOM */
  }

  slot = CURL_HASH_OFFT_SLOT_ADDR(h, id);
  for(he = *slot; he; he = he->next) {
    if(he->id == id) {
      /* existing key entry, overwrite by clearing old pointer */
      hash_offt_entry_clear(h, he);
      he->value = value;
      return TRUE;
    }
  }

  he = hash_offt_mk_entry(id, value);
  if(!he)
    return FALSE; /* OOM */

  hash_offtr_elem_link(h, slot, he);
  return TRUE;
}

bool Curl_hash_offt_remove(struct Curl_hash_offt *h, curl_off_t id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
  if(h->table) {
    struct Curl_hash_offt_entry *he, **he_anchor;

    he_anchor = CURL_HASH_OFFT_SLOT_ADDR(h, id);
    while(*he_anchor) {
      he = *he_anchor;
      if(id == he->id) {
        hash_offt_entry_unlink(h, he_anchor, he);
        hash_offt_entry_destroy(h, he);
        return TRUE;
      }
      he_anchor = &he->next;
    }
  }
  return FALSE;
}

void *Curl_hash_offt_get(struct Curl_hash_offt *h, curl_off_t id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
  if(h->table) {
    struct Curl_hash_offt_entry *he;
    DEBUGASSERT(h->slots);
    he = CURL_HASH_OFFT_SLOT(h, id);
    while(he) {
      if(id == he->id) {
        return he->value;
      }
      he = he->next;
    }
  }
  return NULL;
}

void Curl_hash_offt_clear(struct Curl_hash_offt *h)
{
  if(h && h->table) {
    struct Curl_hash_offt_entry *he, **he_anchor;
    size_t i;
    DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        hash_offt_entry_unlink(h, he_anchor, he);
        hash_offt_entry_destroy(h, he);
      }
    }
  }
}

void
Curl_hash_offt_destroy(struct Curl_hash_offt *h)
{
  DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
  if(h->table) {
    Curl_hash_offt_clear(h);
    Curl_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

size_t Curl_hash_offt_count(struct Curl_hash_offt *h)
{
  DEBUGASSERT(h->init == CURL_HASHOFFTINIT);
  return h->size;
}

/* FOR NOW: basically a duplicate of Curl_hash_offt, BUT we hope to
 * eliminate the offt variant in the near future. */

/* random patterns for API verification */
#ifdef DEBUGBUILD
#define CURL_UINTHASHINIT 0x7117e779
#endif

static unsigned int uint_hash_hash(unsigned int id, unsigned int slots)
{
  return (id % slots);
}


struct uint_hash_entry {
  struct uint_hash_entry *next;
  void   *value;
  unsigned int id;
};

void Curl_uint_hash_init(struct uint_hash *h,
                         unsigned int slots,
                         Curl_uint_hash_dtor *dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);

  h->table = NULL;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
#ifdef DEBUGBUILD
  h->init = CURL_UINTHASHINIT;
#endif
}

static struct uint_hash_entry *uint_hash_mk_entry(unsigned int id, void *value)
{
  struct uint_hash_entry *e;

  /* allocate the struct for the hash entry */
  e = malloc(sizeof(*e));
  if(e) {
    e->id = id;
    e->next = NULL;
    e->value = value;
  }
  return e;
}

static void uint_hash_entry_clear(struct uint_hash *h,
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

static void uint_hash_entry_destroy(struct uint_hash *h,
                                    struct uint_hash_entry *e)
{
  uint_hash_entry_clear(h, e);
  free(e);
}

static void uint_hash_entry_unlink(struct uint_hash *h,
                                   struct uint_hash_entry **he_anchor,
                                   struct uint_hash_entry *he)
{
  *he_anchor = he->next;
  --h->size;
}

static void uint_hash_elem_link(struct uint_hash *h,
                                 struct uint_hash_entry **he_anchor,
                                 struct uint_hash_entry *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

#define CURL_UINT_HASH_SLOT(h,id)  h->table[uint_hash_hash(id, h->slots)]
#define CURL_UINT_HASH_SLOT_ADDR(h,id) &CURL_HASH_OFFT_SLOT(h,id)

bool Curl_uint_hash_set(struct uint_hash *h, unsigned int id, void *value)
{
  struct uint_hash_entry *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_UINTHASHINIT);
  if(!h->table) {
    h->table = calloc(h->slots, sizeof(*he));
    if(!h->table)
      return FALSE; /* OOM */
  }

  slot = CURL_UINT_HASH_SLOT_ADDR(h, id);
  for(he = *slot; he; he = he->next) {
    if(he->id == id) {
      /* existing key entry, overwrite by clearing old pointer */
      uint_hash_entry_clear(h, he);
      he->value = value;
      return TRUE;
    }
  }

  he = uint_hash_mk_entry(id, value);
  if(!he)
    return FALSE; /* OOM */

  uint_hash_elem_link(h, slot, he);
  return TRUE;
}

bool Curl_uint_hash_remove(struct uint_hash *h, unsigned int id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == CURL_UINTHASHINIT);
  if(h->table) {
    struct uint_hash_entry *he, **he_anchor;

    he_anchor = CURL_UINT_HASH_SLOT_ADDR(h, id);
    while(*he_anchor) {
      he = *he_anchor;
      if(id == he->id) {
        uint_hash_entry_unlink(h, he_anchor, he);
        uint_hash_entry_destroy(h, he);
        return TRUE;
      }
      he_anchor = &he->next;
    }
  }
  return FALSE;
}

void *Curl_uint_hash_get(struct uint_hash *h, unsigned int id)
{
  DEBUGASSERT(h);
  DEBUGASSERT(h->init == CURL_UINTHASHINIT);
  if(h->table) {
    struct uint_hash_entry *he;
    DEBUGASSERT(h->slots);
    he = CURL_UINT_HASH_SLOT(h, id);
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
    DEBUGASSERT(h->init == CURL_UINTHASHINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        uint_hash_entry_unlink(h, he_anchor, he);
        uint_hash_entry_destroy(h, he);
      }
    }
  }
}

void
Curl_uint_hash_destroy(struct uint_hash *h)
{
  DEBUGASSERT(h->init == CURL_UINTHASHINIT);
  if(h->table) {
    uint_hash_clear(h);
    Curl_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

unsigned int Curl_uint_hash_count(struct uint_hash *h)
{
  DEBUGASSERT(h->init == CURL_UINTHASHINIT);
  return h->size;
}

void Curl_uint_hash_visit(struct uint_hash *h,
                          Curl_uint_hash_visit_cb *cb,
                          void *user_data)
{
  if(h && h->table && cb) {
    struct uint_hash_entry *he;
    size_t i;
    DEBUGASSERT(h->init == CURL_UINTHASHINIT);
    for(i = 0; i < h->slots; ++i) {
      for(he = h->table[i]; he; he = he->next) {
        if(!cb(he->id, he->value, user_data))
          return;
      }
    }
  }
}
