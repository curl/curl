#ifndef __HASH_H
#define __HASH_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#include <stddef.h>

#include "llist.h"

#define CURL_HASH_KEY_IS_STRING 0
#define CURL_HASH_KEY_IS_NUM    1

typedef void (*curl_hash_dtor)(void *);

typedef struct _curl_hash {
  curl_llist     **table;
  curl_hash_dtor   dtor;
  int              slots;
  size_t           size;
} curl_hash;

typedef struct _curl_hash_key {
  union {
    struct {
      char *val;
      unsigned int len;
    } str;

    unsigned long num;
  } value;

  int type;
} curl_hash_key;

typedef struct _curl_hash_element {
  curl_hash_key  key;
  void          *ptr;
} curl_hash_element;


void curl_hash_init(curl_hash *h, int slots, curl_hash_dtor dtor);
curl_hash *curl_hash_alloc(int slots, curl_hash_dtor dtor);
int curl_hash_add_or_update(curl_hash *h, char *str_key, unsigned int str_key_len, 
			     unsigned long num_key, const void *p);
int curl_hash_extended_delete(curl_hash *h, char *str_key, unsigned int str_key_len, 
			       unsigned long num_key);
int curl_hash_extended_find(curl_hash *h, char *str_key, unsigned int str_key_len, 
			     unsigned long num_key, void **p);
void curl_hash_apply(curl_hash *h, void *user, void (*cb)(void *, curl_hash_element *));
void curl_hash_clean(curl_hash *h);
void curl_hash_destroy(curl_hash *h);

#define curl_hash_find(h, key, key_len, p) curl_hash_extended_find(h, key, key_len, 0, p)
#define curl_hash_delete(h, key, key_len) curl_hash_extended_delete(h, key, key_len, 0)
#define curl_hash_add(h, key, key_len, p) curl_hash_add_or_update(h, key, key_len, 0, p)
#define curl_hash_update curl_hash_add
#define curl_hash_index_find(h, key, p) curl_hash_extended_find(h, NULL, 0, key, p)
#define curl_hash_index_delete(h, key) curl_hash_extended_delete(h, NULL, 0, key)
#define curl_hash_index_add(h, key, p) curl_hash_add_or_update(h, NULL, 0, key, p)
#define curl_hash_index_update curl_hash_index_add

#endif
