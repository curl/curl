/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <string.h>

#include "hash.h"
#include "llist.h"

#ifdef MALLOCDEBUG
/* this must be the last include file */
#include "memdebug.h"
#endif


static unsigned long 
curl_hash_str(const char *key, unsigned int key_length)
{
  register unsigned long h = 0;
  register unsigned long g;
  register char *p = (char *) key;
  register char *end = (char *) key + key_length;

  while (p < end) {
    h = (h << 4) + *p++;
    if ((g = (h & 0xF0000000))) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
  }

  return h;
}

static unsigned long 
curl_hash_num(unsigned long key)
{
  key += ~(key << 15);
  key ^= (key >> 10);
  key += (key << 3);
  key ^= (key >> 6);
  key += (key << 11);
  key ^= (key >> 16);

  return key;
}

static void 
hash_element_dtor(void *u, void *ele)
{
  curl_hash_element *e = (curl_hash_element *) ele; 
  curl_hash         *h = (curl_hash *) u; 
	
  if (e->key.type == CURL_HASH_KEY_IS_STRING) {
    free(e->key.value.str.val);
  }
  h->dtor(e->ptr);

  free(e);
  e = NULL;
}

void 
curl_hash_init(curl_hash *h, int slots, curl_hash_dtor dtor)
{
  int i;

  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;  

  h->table = (curl_llist **) malloc(slots * sizeof(curl_llist *));
  for (i = 0; i < h->slots; ++i) {
    h->table[i] = curl_llist_alloc((curl_llist_dtor) hash_element_dtor);
  }
}

curl_hash *
curl_hash_alloc(int slots, curl_hash_dtor dtor)
{
  curl_hash *h;

  h = (curl_hash *)malloc(sizeof(curl_hash));
  if(NULL = h)
    return NULL;

  curl_hash_init(h, slots, dtor);

  return h;
}

#define FIND_SLOT(__h, __s_key, __s_key_len, __n_key) \
  ((__s_key ? curl_hash_str(__s_key, __s_key_len) : curl_hash_num(__n_key)) % (__h)->slots)

#define KEY_CREATE(__k, __s_key, __s_key_len, __n_key, __dup) \
  if (__s_key) { \
    if (__dup) { \
      (__k)->value.str.val = (char *) malloc(__s_key_len); \
      memcpy((__k)->value.str.val, __s_key, __s_key_len); \
    } else { \
      (__k)->value.str.val = __s_key; \
    } \
    (__k)->value.str.len = __s_key_len; \
    (__k)->type = CURL_HASH_KEY_IS_STRING; \
  } else { \
    (__k)->value.num = __n_key; \
    (__k)->type = CURL_HASH_KEY_IS_NUM; \
  }

#define MIN(a, b) (a > b ? b : a)

static int 
curl_hash_key_compare(curl_hash_key *key1, curl_hash_key *key2)
{
  if (key1->type == CURL_HASH_KEY_IS_NUM) {
    if (key2->type == CURL_HASH_KEY_IS_STRING)
      return 0;

    if (key1->value.num == key2->value.num)
      return 1;
  } else {
    if (key2->type == CURL_HASH_KEY_IS_NUM)
      return 0;

    if (memcmp(key1->value.str.val, key2->value.str.val, 
               MIN(key1->value.str.len, key2->value.str.len)) == 0)
      return 1;
  }

  return 0;
}

int 
curl_hash_add_or_update(curl_hash *h, char *str_key, unsigned int str_key_len, 
                        unsigned long num_key, const void *p)
{
  curl_hash_element  *e;
  curl_hash_key       tmp;
  curl_llist         *l; 
  curl_llist_element *le;
  int                slot;

  slot = FIND_SLOT(h, str_key, str_key_len, num_key);
  l = h->table[slot];
  KEY_CREATE(&tmp, str_key, str_key_len, num_key, 0);
  for (le = CURL_LLIST_HEAD(l); le != NULL; le = CURL_LLIST_NEXT(le)) {
    if (curl_hash_key_compare(&tmp, &((curl_hash_element *) CURL_LLIST_VALP(le))->key)) {
      curl_hash_element *to_update = CURL_LLIST_VALP(le);
      h->dtor(to_update->ptr);
      to_update->ptr = (void *) p;
      return 1;
    }
  }

  e = (curl_hash_element *) malloc(sizeof(curl_hash_element));
  KEY_CREATE(&e->key, str_key, str_key_len, num_key, 1);
  e->ptr = (void *) p;

  if (curl_llist_insert_next(l, CURL_LLIST_TAIL(l), e)) {
    ++h->size;
    return 1;
  } else {
    return 0;
  }
}

int 
curl_hash_extended_delete(curl_hash *h, char *str_key, unsigned int str_key_len, 
                          unsigned long num_key)
{
  curl_llist         *l;
  curl_llist_element *le;
  curl_hash_key       tmp;
  int                slot;

  slot = FIND_SLOT(h, str_key, str_key_len, num_key);
  l = h->table[slot];

  KEY_CREATE(&tmp, str_key, str_key_len, num_key, 0);
  for (le = CURL_LLIST_HEAD(l); le != NULL; le = CURL_LLIST_NEXT(le)) {
    if (curl_hash_key_compare(&tmp, &((curl_hash_element *) CURL_LLIST_VALP(le))->key)) {
      curl_llist_remove(l, le, (void *) h);
      --h->size;
      return 1;
    }
  }

  return 0;
}

int 
curl_hash_extended_find(curl_hash *h, char *str_key, unsigned int str_key_len, 
                        unsigned long num_key, void **p)
{
  curl_llist         *l;
  curl_llist_element *le;
  curl_hash_key       tmp;
  int                slot;

  slot = FIND_SLOT(h, str_key, str_key_len, num_key);
  l = h->table[slot];

  KEY_CREATE(&tmp, str_key, str_key_len, num_key, 0);
  for (le = CURL_LLIST_HEAD(l); le != NULL; le = CURL_LLIST_NEXT(le)) {
    if (curl_hash_key_compare(&tmp, &((curl_hash_element *) CURL_LLIST_VALP(le))->key)) {
      *p = ((curl_hash_element *) CURL_LLIST_VALP(le))->ptr;
      return 1;
    }
  }

  return 0;
}

void 
curl_hash_apply(curl_hash *h, void *user, void (*cb)(void *, curl_hash_element *))
{
  curl_llist_element  *le;
  int                  i;

  for (i = 0; i < h->slots; ++i) {
    for (le = CURL_LLIST_HEAD(h->table[i]); le != NULL; le = CURL_LLIST_NEXT(le)) {
      cb(user, (curl_hash_element *) CURL_LLIST_VALP(le));
    }
  }
}

void
curl_hash_clean(curl_hash *h)
{
  int i;

  for (i = 0; i < h->slots; ++i) {
    curl_llist_destroy(h->table[i], (void *) h);
  }

  free(h->table);
  h->table = NULL;
}

size_t 
curl_hash_count(curl_hash *h)
{
  return h->size;
}

void 
curl_hash_destroy(curl_hash *h)
{
  if (!h) {
    return;
  }

  curl_hash_clean(h);
  free(h);
  h = NULL;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
