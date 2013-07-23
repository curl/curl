/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include "hash.h"
#include "llist.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

static void
hash_element_dtor(void *user, void *element)
{
  struct curl_hash *h = (struct curl_hash *) user;
  struct curl_hash_element *e = (struct curl_hash_element *) element;

  Curl_safefree(e->key);

  if(e->ptr) {
    h->dtor(e->ptr);
    e->ptr = NULL;
  }

  e->key_len = 0;

  free(e);
}

/* return 1 on error, 0 is fine */
int
Curl_hash_init(struct curl_hash *h,
               int slots,
               hash_function hfunc,
               comp_function comparator,
               curl_hash_dtor dtor)
{
  int i;

  if(!slots || !hfunc || !comparator ||!dtor) {
    return 1; /* failure */
  }

  h->hash_func = hfunc;
  h->comp_func = comparator;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;

  h->table = malloc(slots * sizeof(struct curl_llist *));
  if(h->table) {
    for(i = 0; i < slots; ++i) {
      h->table[i] = Curl_llist_alloc((curl_llist_dtor) hash_element_dtor);
      if(!h->table[i]) {
        while(i--) {
          Curl_llist_destroy(h->table[i], NULL);
          h->table[i] = NULL;
        }
        free(h->table);
        h->table = NULL;
        h->slots = 0;
        return 1; /* failure */
      }
    }
    return 0; /* fine */
  }
  else {
    h->slots = 0;
    return 1; /* failure */
  }
}

struct curl_hash *
Curl_hash_alloc(int slots,
                hash_function hfunc,
                comp_function comparator,
                curl_hash_dtor dtor)
{
  struct curl_hash *h;

  if(!slots || !hfunc || !comparator ||!dtor) {
    return NULL; /* failure */
  }

  h = malloc(sizeof(struct curl_hash));
  if(h) {
    if(Curl_hash_init(h, slots, hfunc, comparator, dtor)) {
      /* failure */
      free(h);
      h = NULL;
    }
  }

  return h;
}



static struct curl_hash_element *
mk_hash_element(const void *key, size_t key_len, const void *p)
{
  struct curl_hash_element *he = malloc(sizeof(struct curl_hash_element));

  if(he) {
    void *dupkey = malloc(key_len);
    if(dupkey) {
      /* copy the key */
      memcpy(dupkey, key, key_len);

      he->key = dupkey;
      he->key_len = key_len;
      he->ptr = (void *) p;
    }
    else {
      /* failed to duplicate the key, free memory and fail */
      free(he);
      he = NULL;
    }
  }
  return he;
}

#define FETCH_LIST(x,y,z) x->table[x->hash_func(y, z, x->slots)]

/* Insert the data in the hash. If there already was a match in the hash,
 * that data is replaced.
 *
 * @unittest: 1305
 */
void *
Curl_hash_add(struct curl_hash *h, void *key, size_t key_len, void *p)
{
  struct curl_hash_element  *he;
  struct curl_llist_element *le;
  struct curl_llist *l = FETCH_LIST (h, key, key_len);

  for(le = l->head; le; le = le->next) {
    he = (struct curl_hash_element *) le->ptr;
    if(h->comp_func(he->key, he->key_len, key, key_len)) {
      Curl_llist_remove(l, le, (void *)h);
      --h->size;
      break;
    }
  }

  he = mk_hash_element(key, key_len, p);
  if(he) {
    if(Curl_llist_insert_next(l, l->tail, he)) {
      ++h->size;
      return p; /* return the new entry */
    }
    /*
     * Couldn't insert it, destroy the 'he' element and the key again. We
     * don't call hash_element_dtor() since that would also call the
     * "destructor" for the actual data 'p'. When we fail, we shall not touch
     * that data.
     */
    free(he->key);
    free(he);
  }

  return NULL; /* failure */
}

/* remove the identified hash entry, returns non-zero on failure */
int Curl_hash_delete(struct curl_hash *h, void *key, size_t key_len)
{
  struct curl_llist_element *le;
  struct curl_hash_element  *he;
  struct curl_llist *l = FETCH_LIST(h, key, key_len);

  for(le = l->head; le; le = le->next) {
    he = le->ptr;
    if(h->comp_func(he->key, he->key_len, key, key_len)) {
      Curl_llist_remove(l, le, (void *) h);
      --h->size;
      return 0;
    }
  }
  return 1;
}

void *
Curl_hash_pick(struct curl_hash *h, void *key, size_t key_len)
{
  struct curl_llist_element *le;
  struct curl_hash_element  *he;
  struct curl_llist *l;

  if(h) {
    l = FETCH_LIST(h, key, key_len);
    for(le = l->head; le; le = le->next) {
      he = le->ptr;
      if(h->comp_func(he->key, he->key_len, key, key_len)) {
        return he->ptr;
      }
    }
  }

  return NULL;
}

#if defined(DEBUGBUILD) && defined(AGGRESIVE_TEST)
void
Curl_hash_apply(curl_hash *h, void *user,
                void (*cb)(void *user, void *ptr))
{
  struct curl_llist_element  *le;
  int                  i;

  for(i = 0; i < h->slots; ++i) {
    for(le = (h->table[i])->head;
        le;
        le = le->next) {
      curl_hash_element *el = le->ptr;
      cb(user, el->ptr);
    }
  }
}
#endif

void
Curl_hash_clean(struct curl_hash *h)
{
  int i;

  for(i = 0; i < h->slots; ++i) {
    Curl_llist_destroy(h->table[i], (void *) h);
    h->table[i] = NULL;
  }

  Curl_safefree(h->table);
  h->size = 0;
  h->slots = 0;
}

void
Curl_hash_clean_with_criterium(struct curl_hash *h, void *user,
                               int (*comp)(void *, void *))
{
  struct curl_llist_element *le;
  struct curl_llist_element *lnext;
  struct curl_llist *list;
  int i;

  if(!h)
    return;

  for(i = 0; i < h->slots; ++i) {
    list = h->table[i];
    le = list->head; /* get first list entry */
    while(le) {
      struct curl_hash_element *he = le->ptr;
      lnext = le->next;
      /* ask the callback function if we shall remove this entry or not */
      if(comp(user, he->ptr)) {
        Curl_llist_remove(list, le, (void *) h);
        --h->size; /* one less entry in the hash now */
      }
      le = lnext;
    }
  }
}

void
Curl_hash_destroy(struct curl_hash *h)
{
  if(!h)
    return;

  Curl_hash_clean(h);

  free(h);
}

size_t Curl_hash_str(void* key, size_t key_length, size_t slots_num)
{
  const char* key_str = (const char *) key;
  const char *end = key_str + key_length;
  unsigned long h = 5381;

  while(key_str < end) {
    h += h << 5;
    h ^= (unsigned long) *key_str++;
  }

  return (h % slots_num);
}

size_t Curl_str_key_compare(void*k1, size_t key1_len, void*k2, size_t key2_len)
{
  char *key1 = (char *)k1;
  char *key2 = (char *)k2;

  if(key1_len == key2_len &&
      *key1 == *key2 &&
      memcmp(key1, key2, key1_len) == 0) {
    return 1;
  }

  return 0;
}

void Curl_hash_start_iterate(struct curl_hash *hash,
                             struct curl_hash_iterator *iter)
{
  iter->hash = hash;
  iter->slot_index = 0;
  iter->current_element = NULL;
}

struct curl_hash_element *
Curl_hash_next_element(struct curl_hash_iterator *iter)
{
  int i;
  struct curl_hash *h = iter->hash;

  /* Get the next element in the current list, if any */
  if(iter->current_element)
    iter->current_element = iter->current_element->next;

  /* If we have reached the end of the list, find the next one */
  if(!iter->current_element) {
    for(i = iter->slot_index;i < h->slots;i++) {
      if(h->table[i]->head) {
        iter->current_element = h->table[i]->head;
        iter->slot_index = i+1;
        break;
      }
    }
  }

  if(iter->current_element) {
    struct curl_hash_element *he = iter->current_element->ptr;
    return he;
  }
  else {
    iter->current_element = NULL;
    return NULL;
  }
}

#if 0 /* useful function for debugging hashes and their contents */
void Curl_hash_print(struct curl_hash *h,
                     void (*func)(void *))
{
  struct curl_hash_iterator iter;
  struct curl_hash_element *he;
  int last_index = -1;

  if(!h)
    return;

  fprintf(stderr, "=Hash dump=\n");

  Curl_hash_start_iterate(h, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(iter.slot_index != last_index) {
      fprintf(stderr, "index %d:", iter.slot_index);
      if(last_index >= 0) {
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
