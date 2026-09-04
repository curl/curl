#ifndef HEADER_CURL_HASH_H
#define HEADER_CURL_HASH_H
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

typedef void (*Curl_hash_dtor)(void *);

typedef void (*Curl_hash_elem_dtor)(void *key, size_t key_len, void *p);

/* How keys in a hash are interpreted. */
typedef enum {
  CURL_HASH_TYPE_BYTES,
  CURL_HASH_TYPE_SOCKET,
  CURL_HASH_TYPE_LAST
} Curl_hash_type;

struct Curl_hash_element {
  struct Curl_hash_element *next;
  void *ptr;
  Curl_hash_elem_dtor dtor;
  size_t key_len;
  char key[1]; /* allocated memory following the struct */
};

struct Curl_hash {
  struct Curl_hash_element **table;
  /* General element destructor, unless element itself carries one */
  Curl_hash_dtor dtor;
  size_t slots;
  size_t size;
  uint8_t type; /* Curl_hash_type */
#ifdef DEBUGBUILD
  int init;
#endif
};

struct Curl_hash_iterator {
  struct Curl_hash *hash;
  size_t slot_index;
  struct Curl_hash_element *current;
#ifdef DEBUGBUILD
  int init;
#endif
};

void Curl_hash_init(struct Curl_hash *h,
                    size_t slots,
                    Curl_hash_type type,
                    Curl_hash_dtor dtor);

void *Curl_hash_add(struct Curl_hash *h, void *key, size_t key_len, void *p);
void *Curl_hash_add2(struct Curl_hash *h, void *key, size_t key_len, void *p,
                     Curl_hash_elem_dtor dtor);
int Curl_hash_delete(struct Curl_hash *h, void *key, size_t key_len);
void *Curl_hash_pick(struct Curl_hash *h, void *key, size_t key_len);

void Curl_hash_destroy(struct Curl_hash *h);
size_t Curl_hash_count(struct Curl_hash *h);
void Curl_hash_clean(struct Curl_hash *h);
void Curl_hash_clean_with_criterium(struct Curl_hash *h, void *user,
                                    int (*comp)(void *, void *));
size_t Curl_hash_str(void *key, size_t key_length, size_t slots_num);
void Curl_hash_start_iterate(struct Curl_hash *hash,
                             struct Curl_hash_iterator *iter);
struct Curl_hash_element *Curl_hash_next_element(
  struct Curl_hash_iterator *iter);

void Curl_hash_print(struct Curl_hash *h, void (*func)(void *));

#endif /* HEADER_CURL_HASH_H */
