#ifndef HEADER_CURL_UINT_SPBSET_H
#define HEADER_CURL_UINT_SPBSET_H
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

/* A "sparse" bitset for unsigned int values.
 * It can hold any unsigned int value.
 *
 * Optimized for the case where only a small set of numbers need
 * to be kept, especially when "close" together. Then storage space
 * is most efficient, deteriorating when many number are far apart.
 */

/* 4 slots = 256 bits, keep this a 2^n value. */
#define CURL_UINT_SPBSET_CH_SLOTS  4
#define CURL_UINT_SPBSET_CH_MASK   ((CURL_UINT_SPBSET_CH_SLOTS * 64) - 1)

/* store the uint value from offset to
 * (offset + (CURL_UINT_SPBSET_CHUNK_SLOTS * 64) - 1 */
struct uint_spbset_chunk {
  struct uint_spbset_chunk *next;
  curl_uint64_t slots[CURL_UINT_SPBSET_CH_SLOTS];
  unsigned int offset;
};

struct uint_spbset {
  struct uint_spbset_chunk head;
#ifdef DEBUGBUILD
  int init;
#endif
};

void Curl_uint_spbset_init(struct uint_spbset *bset);

void Curl_uint_spbset_destroy(struct uint_spbset *bset);

/* Get the cardinality of the bitset, e.g. numbers present in the set. */
unsigned int Curl_uint_spbset_count(struct uint_spbset *bset);

/* TRUE of bitset is empty */
bool Curl_uint_spbset_empty(struct uint_spbset *bset);

/* Clear the bitset, making it empty. */
void Curl_uint_spbset_clear(struct uint_spbset *bset);

/* Add the number `i` to the bitset.
 * Numbers can be added more than once, without making a difference.
 * Returns FALSE if allocations failed. */
bool Curl_uint_spbset_add(struct uint_spbset *bset, unsigned int i);

/* Remove the number `i` from the bitset. */
void Curl_uint_spbset_remove(struct uint_spbset *bset, unsigned int i);

/* Return TRUE if the bitset contains number `i`. */
bool Curl_uint_spbset_contains(struct uint_spbset *bset, unsigned int i);

/* Get the first number in the bitset, e.g. the smallest.
 * Returns FALSE when the bitset is empty. */
bool Curl_uint_spbset_first(struct uint_spbset *bset, unsigned int *pfirst);

/* Get the next number in the bitset, following `last` in natural order.
 * Put another way, this is the smallest number greater than `last` in
 * the bitset. `last` does not have to be present in the set.
 *
 * Returns FALSE when no such number is in the set.
 *
 * This allows to iterate the set while being modified:
 * - added numbers higher than 'last' will be picked up by the iteration.
 * - added numbers lower than 'last' will not show up.
 * - removed numbers lower or equal to 'last' will not show up.
 * - removed numbers higher than 'last' will not be visited. */
bool Curl_uint_spbset_next(struct uint_spbset *bset, unsigned int last,
                           unsigned int *pnext);

#endif /* HEADER_CURL_UINT_SPBSET_H */
