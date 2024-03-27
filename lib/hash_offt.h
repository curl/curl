#ifndef HEADER_CURL_HASH_OFFT_H
#define HEADER_CURL_HASH_OFFT_H
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

#include <stddef.h>

#include "llist.h"

typedef void Curl_hash_offt_dtor(void *elem, void *user_data);

struct Curl_hash_offt {
  struct Curl_llist *table;
  Curl_hash_offt_dtor *dtor;
  void *dtor_user_data;
  unsigned int slots;
  size_t size;
  unsigned char bits;
};

struct Curl_hash_offt_entry {
  struct Curl_llist_element list;
  void   *elem;
  curl_off_t id;
};

struct Curl_hash_offt_iterator {
  struct Curl_hash_offt *hash;
  int slot_index;
  struct Curl_llist_element *current_element;
};

/**
 * Init the hash for keeping (2^bits) slots. This does not limit
 * the number of entries that can be stored.
 */
void Curl_hash_offt_init(struct Curl_hash_offt *h,
                         unsigned char bits,
                         Curl_hash_offt_dtor *dtor,
                         void *dtor_user_data);

void *Curl_hash_offt_set(struct Curl_hash_offt *h, curl_off_t id, void *elem);
int Curl_hash_offt_remove(struct Curl_hash_offt *h, curl_off_t id);
void *Curl_hash_offt_get(struct Curl_hash_offt *h, curl_off_t id);
#define Curl_hash_offt_count(h) ((h)->size)
void Curl_hash_offt_reset(struct Curl_hash_offt *h);
void Curl_hash_offt_destroy(struct Curl_hash_offt *h);

struct Curl_hash_offt_entry *
Curl_hash_offt_iter_first(struct Curl_hash_offt *hash,
                          struct Curl_hash_offt_iterator *iter);
struct Curl_hash_offt_entry *
Curl_hash_offt_iter_next(struct Curl_hash_offt_iterator *iter);

#endif /* HEADER_CURL_HASH_OFFT_H */
