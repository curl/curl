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
#include "uint-bset.h"

#ifdef DEBUGBUILD
#define CURL_UINT32_BSET_MAGIC  0x62757473
#endif

void Curl_uint32_bset_init(struct uint32_bset *bset)
{
  memset(bset, 0, sizeof(*bset));
#ifdef DEBUGBUILD
  bset->init = CURL_UINT32_BSET_MAGIC;
#endif
}

CURLcode Curl_uint32_bset_resize(struct uint32_bset *bset, uint32_t nmax)
{
  uint32_t nslots = (nmax < (UINT32_MAX - 63)) ?
                    ((nmax + 63) / 64) : (UINT32_MAX / 64);

  DEBUGASSERT(bset->init == CURL_UINT32_BSET_MAGIC);
  if(nslots != bset->nslots) {
    uint64_t *slots = curlx_calloc(nslots, sizeof(uint64_t));
    if(!slots)
      return CURLE_OUT_OF_MEMORY;

    if(bset->slots) {
      memcpy(slots, bset->slots,
             (CURLMIN(nslots, bset->nslots) * sizeof(uint64_t)));
      curlx_free(bset->slots);
    }
    bset->slots = slots;
    bset->nslots = nslots;
    bset->first_slot_used = 0;
  }
  return CURLE_OK;
}

void Curl_uint32_bset_destroy(struct uint32_bset *bset)
{
  DEBUGASSERT(bset->init == CURL_UINT32_BSET_MAGIC);
  curlx_free(bset->slots);
  memset(bset, 0, sizeof(*bset));
}

#ifdef UNITTESTS
UNITTEST uint32_t Curl_uint32_bset_capacity(struct uint32_bset *bset)
{
  return bset->nslots * 64;
}
#endif

uint32_t Curl_uint32_bset_count(struct uint32_bset *bset)
{
  uint32_t i;
  uint32_t n = 0;
  for(i = 0; i < bset->nslots; ++i) {
    if(bset->slots[i])
      n += CURL_POPCOUNT64(bset->slots[i]);
  }
  return n;
}

bool Curl_uint32_bset_empty(struct uint32_bset *bset)
{
  uint32_t i;
  for(i = bset->first_slot_used; i < bset->nslots; ++i) {
    if(bset->slots[i])
      return FALSE;
  }
  return TRUE;
}

void Curl_uint32_bset_clear(struct uint32_bset *bset)
{
  if(bset->nslots) {
    memset(bset->slots, 0, bset->nslots * sizeof(uint64_t));
    bset->first_slot_used = UINT32_MAX;
  }
}

bool Curl_uint32_bset_add(struct uint32_bset *bset, uint32_t i)
{
  uint32_t islot = i / 64;
  if(islot >= bset->nslots)
    return FALSE;
  bset->slots[islot] |= ((uint64_t)1 << (i % 64));
  if(islot < bset->first_slot_used)
    bset->first_slot_used = islot;
  return TRUE;
}

void Curl_uint32_bset_remove(struct uint32_bset *bset, uint32_t i)
{
  size_t islot = i / 64;
  if(islot < bset->nslots)
    bset->slots[islot] &= ~((uint64_t)1 << (i % 64));
}

bool Curl_uint32_bset_contains(struct uint32_bset *bset, uint32_t i)
{
  uint32_t islot = i / 64;
  if(islot >= bset->nslots)
    return FALSE;
  return (bset->slots[islot] & ((uint64_t)1 << (i % 64))) != 0;
}

bool Curl_uint32_bset_first(struct uint32_bset *bset, uint32_t *pfirst)
{
  uint32_t i;
  for(i = bset->first_slot_used; i < bset->nslots; ++i) {
    if(bset->slots[i]) {
      *pfirst = (i * 64) + CURL_CTZ64(bset->slots[i]);
      bset->first_slot_used = i;
      return TRUE;
    }
  }
  bset->first_slot_used = *pfirst = UINT32_MAX;
  return FALSE;
}

bool Curl_uint32_bset_next(struct uint32_bset *bset, uint32_t last,
                           uint32_t *pnext)
{
  uint32_t islot;
  uint64_t x;

  ++last; /* look for number one higher than last */
  islot = last / 64; /* the slot this would be in */
  if(islot < bset->nslots) {
    /* shift away the bits we already iterated in this slot */
    x = (bset->slots[islot] >> (last % 64));
    if(x) {
      /* more bits set, next is `last` + trailing0s of the shifted slot */
      *pnext = last + CURL_CTZ64(x);
      return TRUE;
    }
    /* no more bits set in the last slot, scan forward */
    for(islot = islot + 1; islot < bset->nslots; ++islot) {
      if(bset->slots[islot]) {
        *pnext = (islot * 64) + CURL_CTZ64(bset->slots[islot]);
        return TRUE;
      }
    }
  }
  *pnext = UINT32_MAX; /* a value we cannot store */
  return FALSE;
}

#ifdef CURL_POPCOUNT64_IMPLEMENT
uint32_t Curl_popcount64(uint64_t x)
{
  /* Compute the "Hamming Distance" between 'x' and 0,
   * which is the number of set bits in 'x'.
   * See: https://en.wikipedia.org/wiki/Hamming_weight */
  const uint64_t m1  = 0x5555555555555555LL; /* 0101+ */
  const uint64_t m2  = 0x3333333333333333LL; /* 00110011+ */
  const uint64_t m4  = 0x0f0f0f0f0f0f0f0fLL; /* 00001111+ */
   /* 1 + 256^1 + 256^2 + 256^3 + ... + 256^7 */
  const uint64_t h01 = 0x0101010101010101LL;
  x -= (x >> 1) & m1;             /* replace every 2 bits with bits present */
  x = (x & m2) + ((x >> 2) & m2); /* replace every nibble with bits present */
  x = (x + (x >> 4)) & m4;        /* replace every byte with bits present */
  /* top 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ... which makes the
   * top byte the sum of all individual 8 bytes, throw away the rest */
  return (uint32_t)((x * h01) >> 56);
}
#endif /* CURL_POPCOUNT64_IMPLEMENT */

#ifdef CURL_CTZ64_IMPLEMENT
uint32_t Curl_ctz64(uint64_t x)
{
  /* count trailing zeros in a uint64_t.
   * divide and conquer to find the number of lower 0 bits */
  const uint64_t ml32 = 0xFFFFFFFF; /* lower 32 bits */
  const uint64_t ml16 = 0x0000FFFF; /* lower 16 bits */
  const uint64_t ml8  = 0x000000FF; /* lower 8 bits */
  const uint64_t ml4  = 0x0000000F; /* lower 4 bits */
  const uint64_t ml2  = 0x00000003; /* lower 2 bits */
  uint32_t n;

  if(!x)
    return 64;
  n = 1;
  if(!(x & ml32)) {
    n = n + 32;
    x = x >> 32;
  }
  if(!(x & ml16)) {
    n = n + 16;
    x = x >> 16;
  }
  if(!(x & ml8)) {
    n = n + 8;
    x = x >> 8;
  }
  if(!(x & ml4)) {
    n = n + 4;
    x = x >> 4;
  }
  if(!(x & ml2)) {
    n = n + 2;
    x = x >> 2;
  }
  return n - (uint32_t)(x & 1);
}
#endif /* CURL_CTZ64_IMPLEMENT */
