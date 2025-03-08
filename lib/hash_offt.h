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


typedef bool Curl_hash_offt_visit_cb(curl_off_t id, void *value,
                                     void *user_data);

void Curl_hash_offt_visit(struct Curl_hash_offt *h,
                          Curl_hash_offt_visit_cb *cb,
                          void *user_data);


#endif /* HEADER_CURL_HASH_OFFT_H */
