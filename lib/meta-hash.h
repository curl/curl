#ifndef HEADER_CURL_META_HASH_H
#define HEADER_CURL_META_HASH_H
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

/* A hash of "meta type" values */

struct dynbuf;
struct meta_key;

typedef void Curl_meta_hash_dtor(const struct meta_key *key,
                                 void *value);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
typedef CURLcode Curl_meta_hash_print(struct dynbuf *buf,
                                      const struct meta_key *key,
                                      void *value);
#endif

typedef enum {
  CURL_META_STR,    /* value is a C-string */
  CURL_META_PTR,    /* value is an opaque pointer */
} meta_type;

/* A meta key for lookups into the hash table.
 * Lifetime: forever, declared as static */
struct meta_key {
  const char *id;
  size_t id_len;
  Curl_meta_hash_dtor *dtor;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  Curl_meta_hash_print *print;
#endif
  meta_type type;
};

struct meta_hash_entry;

/* Hash for `meta_key` values */
struct meta_hash {
  struct meta_hash_entry **table;
  unsigned int slots;
  unsigned int size;
#ifdef DEBUGBUILD
  int init;
#endif
};


void Curl_meta_hash_init(struct meta_hash *h, unsigned int slots);
void Curl_meta_hash_destroy(struct meta_hash *h);
void Curl_meta_hash_clear(struct meta_hash *h);

bool Curl_meta_hash_remove(struct meta_hash *h, const struct meta_key *key);

/* Set the value for a key. The key is not copied and needs to live
 * longer than the hash itself.
 * The call takes ownership of `value` in any outcome, using the
 * meta key destructor to deallocate it.
 * Returns TRUE if value was successfully stored in the hash. */
bool Curl_meta_hash_set(struct meta_hash *h,
                        const struct meta_key *key, void *value);

void *Curl_meta_hash_get(struct meta_hash *h, const struct meta_key *key);


/* Declaring meta keys */

void Curl_meta_str_dtor(const struct meta_key *key, void *value);


#ifndef CURL_DISABLE_VERBOSE_STRINGS
CURLcode Curl_meta_str_print(struct dynbuf *buf,
                             const struct meta_key *key, void *value);

#define CURL_META_KEY_PTR(id, dtor, print) \
    { STRCONST(id), (dtor), (print), CURL_META_PTR }

#define CURL_META_KEY_STR(id) \
    { STRCONST(id), Curl_meta_str_dtor, Curl_meta_str_print, CURL_META_STR }
#else
#define CURL_META_KEY(id, dtor, print) \
    { STRCONST(id), (dtor), CURL_META_PTR }
#define CURL_META_KEY_STR(id) \
    { STRCONST(id), Curl_meta_str_dtor, CURL_META_STR }
#endif

#endif /* HEADER_CURL_META_HASH_H */
