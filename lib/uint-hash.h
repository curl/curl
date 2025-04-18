#ifndef HEADER_CURL_UINT_HASH_H
#define HEADER_CURL_UINT_HASH_H
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
void Curl_uint_hash_clear(struct uint_hash *h);

bool Curl_uint_hash_set(struct uint_hash *h, unsigned int id, void *value);
bool Curl_uint_hash_remove(struct uint_hash *h, unsigned int id);
void *Curl_uint_hash_get(struct uint_hash *h, unsigned int id);
unsigned int Curl_uint_hash_count(struct uint_hash *h);


typedef bool Curl_uint_hash_visit_cb(unsigned int id, void *value,
                                     void *user_data);

void Curl_uint_hash_visit(struct uint_hash *h,
                          Curl_uint_hash_visit_cb *cb,
                          void *user_data);

#endif /* HEADER_CURL_UINT_HASH_H */
