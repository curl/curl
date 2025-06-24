#ifndef HEADER_CURL_UINT_TABLE_H
#define HEADER_CURL_UINT_TABLE_H
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

/* Destructor for a single table entry */
typedef void Curl_uint_tbl_entry_dtor(unsigned int key, void *entry);

struct uint_tbl {
  void **rows;  /* array of void* holding entries */
  Curl_uint_tbl_entry_dtor *entry_dtor;
  unsigned int nrows;  /* length of `rows` array */
  unsigned int nentries; /* entries in table */
  unsigned int last_key_added; /* UINT_MAX or last key added */
#ifdef DEBUGBUILD
  int init;
#endif
};

/* Initialize the table with 0 capacity.
 * The optional `entry_dtor` is called when a table entry is removed,
 * Passing NULL means no action is taken on removal. */
void Curl_uint_tbl_init(struct uint_tbl *tbl,
                        Curl_uint_tbl_entry_dtor *entry_dtor);

/* Resize the table to change capacity `nmax`. When `nmax` is reduced,
 * all present entries with key equal or larger to `nmax` are removed. */
CURLcode Curl_uint_tbl_resize(struct uint_tbl *tbl, unsigned int nmax);

/* Destroy the table, freeing all entries. */
void Curl_uint_tbl_destroy(struct uint_tbl *tbl);

/* Get the table capacity. */
unsigned int Curl_uint_tbl_capacity(struct uint_tbl *tbl);

/* Get the number of entries in the table. */
unsigned int Curl_uint_tbl_count(struct uint_tbl *tbl);

/* Get the entry for key or NULL if not present */
void *Curl_uint_tbl_get(struct uint_tbl *tbl, unsigned int key);

/* Add a new entry to the table and assign it a free key.
 * Returns FALSE if the table is full.
 *
 * Keys are assigned in a round-robin manner.
 * No matter the capacity, UINT_MAX is never assigned. */
bool Curl_uint_tbl_add(struct uint_tbl *tbl, void *entry, unsigned int *pkey);

/* Remove the entry with `key`. */
void Curl_uint_tbl_remove(struct uint_tbl *tbl, unsigned int key);

/* Return TRUE if the table contains an tryn with that keys. */
bool Curl_uint_tbl_contains(struct uint_tbl *tbl, unsigned int key);

/* Get the first entry in the table (with the smallest `key`).
 * Returns FALSE if the table is empty. */
bool Curl_uint_tbl_first(struct uint_tbl *tbl,
                         unsigned int *pkey, void **pentry);

/* Get the next key in the table, following `last_key` in natural order.
 * Put another way, this is the smallest key greater than `last_key` in
 * the table. `last_key` does not have to be present in the table.
 *
 * Returns FALSE when no such entry is in the table.
 *
 * This allows to iterate the table while being modified:
 * - added keys higher than 'last_key' will be picked up by the iteration.
 * - added keys lower than 'last_key' will not show up.
 * - removed keys lower or equal to 'last_key' will not show up.
 * - removed keys higher than 'last_key' will not be visited. */
bool Curl_uint_tbl_next(struct uint_tbl *tbl, unsigned int last_key,
                        unsigned int *pkey, void **pentry);

#endif /* HEADER_CURL_UINT_TABLE_H */
