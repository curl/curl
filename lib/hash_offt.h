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

struct Curl_hash_offt_entry;
typedef void Curl_hash_offt_dtor(curl_off_t id, void *value);

/* Hash for `curl_off_t` as key */
struct Curl_hash_offt {
  struct Curl_hash_offt_entry **table;
  Curl_hash_offt_dtor *dtor;
  size_t slots;
  size_t size;
#ifdef DEBUGBUILD
  int init;
#endif
};

void Curl_hash_offt_init(struct Curl_hash_offt *h,
                         size_t slots,
                         Curl_hash_offt_dtor *dtor);
void Curl_hash_offt_destroy(struct Curl_hash_offt *h);

bool Curl_hash_offt_set(struct Curl_hash_offt *h, curl_off_t id, void *value);
bool Curl_hash_offt_remove(struct Curl_hash_offt *h, curl_off_t id);
void *Curl_hash_offt_get(struct Curl_hash_offt *h, curl_off_t id);
void Curl_hash_offt_clear(struct Curl_hash_offt *h);
size_t Curl_hash_offt_count(struct Curl_hash_offt *h);


/* A version with unsigned int as key */
typedef void Curl_uint_hash_dtor(unsigned int id, void *value);
struct uint_hash_entry;

/* Hash for `unsigned int` as key */
struct uint_hash {
  struct uint_hash_entry **table;
  Curl_uint_hash_dtor *dtor;
  unsigned int slots;
  unsigned int size;
#ifdef DEBUGBUILD
  int init;
#endif
};


void Curl_uint_hash_init(struct uint_hash *h,
                         unsigned int slots,
                         Curl_uint_hash_dtor *dtor);
void Curl_uint_hash_destroy(struct uint_hash *h);

bool Curl_uint_hash_set(struct uint_hash *h, unsigned int id, void *value);
bool Curl_uint_hash_remove(struct uint_hash *h, unsigned int id);
void *Curl_uint_hash_get(struct uint_hash *h, unsigned int id);
unsigned int Curl_uint_hash_count(struct uint_hash *h);


typedef bool Curl_uint_hash_visit_cb(unsigned int id, void *value,
                                     void *user_data);

void Curl_uint_hash_visit(struct uint_hash *h,
                          Curl_uint_hash_visit_cb *cb,
                          void *user_data);

#endif /* HEADER_CURL_HASH_OFFT_H */
