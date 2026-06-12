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

/* A "sparse" bitset for uint32_t values.
 * It can hold any uint32_t value.
 *
 * Optimized for the case where only a small set of numbers need
 * to be kept, especially when "close" together. Then storage space
 * is most efficient, deteriorating when many number are far apart.
 */

/* 4 slots = 256 bits, keep this a 2^n value. */
#define CURL_UINT32_SPBSET_CH_SLOTS  4
#define CURL_UINT32_SPBSET_CH_MASK   ((CURL_UINT32_SPBSET_CH_SLOTS * 64) - 1)

/* store the uint value from offset to
 * (offset + (CURL_UINT32_SPBSET_CHUNK_SLOTS * 64) - 1 */
struct uint32_spbset_chunk {
  struct uint32_spbset_chunk *next;
  uint64_t slots[CURL_UINT32_SPBSET_CH_SLOTS];
  uint32_t offset;
};

struct uint32_spbset {
  struct uint32_spbset_chunk head;
#ifdef DEBUGBUILD
  int init;
#endif
};

void Curl_uint32_spbset_init(struct uint32_spbset *bset);

void Curl_uint32_spbset_destroy(struct uint32_spbset *bset);

/* Get the cardinality of the bitset, e.g. numbers present in the set. */
uint32_t Curl_uint32_spbset_count(struct uint32_spbset *bset);

/* Add the number `i` to the bitset.
 * Numbers can be added more than once, without making a difference.
 * Returns FALSE if allocations failed. */
bool Curl_uint32_spbset_add(struct uint32_spbset *bset, uint32_t i);

/* Remove the number `i` from the bitset. */
void Curl_uint32_spbset_remove(struct uint32_spbset *bset, uint32_t i);

/* Return TRUE if the bitset contains number `i`. */
bool Curl_uint32_spbset_contains(struct uint32_spbset *bset, uint32_t i);

/* Get the first number in the bitset, e.g. the smallest.
 * Returns FALSE when the bitset is empty. */
bool Curl_uint32_spbset_first(struct uint32_spbset *bset, uint32_t *pfirst);

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
bool Curl_uint32_spbset_next(struct uint32_spbset *bset, uint32_t last,
                             uint32_t *pnext);

#endif /* HEADER_CURL_UINT_SPBSET_H */
