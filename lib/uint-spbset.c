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
#include "uint-spbset.h"

#ifdef DEBUGBUILD
#define CURL_UINT32_SPBSET_MAGIC  0x70737362
#endif

/* Clear the bitset, making it empty. */
UNITTEST void Curl_uint32_spbset_clear(struct uint32_spbset *bset);

void Curl_uint32_spbset_init(struct uint32_spbset *bset)
{
  memset(bset, 0, sizeof(*bset));
#ifdef DEBUGBUILD
  bset->init = CURL_UINT32_SPBSET_MAGIC;
#endif
}

void Curl_uint32_spbset_destroy(struct uint32_spbset *bset)
{
  DEBUGASSERT(bset->init == CURL_UINT32_SPBSET_MAGIC);
  Curl_uint32_spbset_clear(bset);
}

uint32_t Curl_uint32_spbset_count(struct uint32_spbset *bset)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t i, n = 0;

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    for(i = 0; i < CURL_UINT32_SPBSET_CH_SLOTS; ++i) {
      if(chunk->slots[i])
        n += CURL_POPCOUNT64(chunk->slots[i]);
    }
  }
  return n;
}

UNITTEST void Curl_uint32_spbset_clear(struct uint32_spbset *bset)
{
  struct uint32_spbset_chunk *next, *chunk;

  for(chunk = bset->head.next; chunk; chunk = next) {
    next = chunk->next;
    curlx_free(chunk);
  }
  memset(&bset->head, 0, sizeof(bset->head));
}

static struct uint32_spbset_chunk *
uint32_spbset_get_chunk(struct uint32_spbset *bset, uint32_t i, bool grow)
{
  struct uint32_spbset_chunk *chunk, **panchor = NULL;
  uint32_t i_offset = (i & ~CURL_UINT32_SPBSET_CH_MASK);

  if(!bset)
    return NULL;

  for(chunk = &bset->head; chunk;
      panchor = &chunk->next, chunk = chunk->next) {
    if(chunk->offset == i_offset) {
      return chunk;
    }
    else if(chunk->offset > i_offset) {
      /* need new chunk here */
      chunk = NULL;
      break;
    }
  }

  if(!grow)
    return NULL;

  /* need a new one */
  chunk = curlx_calloc(1, sizeof(*chunk));
  if(!chunk)
    return NULL;

  if(panchor) {  /* insert between panchor and *panchor */
    chunk->next = *panchor;
    *panchor = chunk;
  }
  else {  /* prepend to head, switching places */
    memcpy(chunk, &bset->head, sizeof(*chunk));
    memset(&bset->head, 0, sizeof(bset->head));
    bset->head.next = chunk;
  }
  chunk->offset = i_offset;
  return chunk;
}

bool Curl_uint32_spbset_add(struct uint32_spbset *bset, uint32_t i)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t i_chunk;

  chunk = uint32_spbset_get_chunk(bset, i, TRUE);
  if(!chunk)
    return FALSE;

  DEBUGASSERT(i >= chunk->offset);
  i_chunk = (i - chunk->offset);
  DEBUGASSERT((i_chunk / 64) < CURL_UINT32_SPBSET_CH_SLOTS);
  chunk->slots[(i_chunk / 64)] |= ((uint64_t)1 << (i_chunk % 64));
  return TRUE;
}

void Curl_uint32_spbset_remove(struct uint32_spbset *bset, uint32_t i)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t i_chunk;

  chunk = uint32_spbset_get_chunk(bset, i, FALSE);
  if(chunk) {
    DEBUGASSERT(i >= chunk->offset);
    i_chunk = (i - chunk->offset);
    DEBUGASSERT((i_chunk / 64) < CURL_UINT32_SPBSET_CH_SLOTS);
    chunk->slots[(i_chunk / 64)] &= ~((uint64_t)1 << (i_chunk % 64));
  }
}

bool Curl_uint32_spbset_contains(struct uint32_spbset *bset, uint32_t i)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t i_chunk;

  chunk = uint32_spbset_get_chunk(bset, i, FALSE);
  if(chunk) {
    DEBUGASSERT(i >= chunk->offset);
    i_chunk = (i - chunk->offset);
    DEBUGASSERT((i_chunk / 64) < CURL_UINT32_SPBSET_CH_SLOTS);
    return (chunk->slots[i_chunk / 64] &
            ((uint64_t)1 << (i_chunk % 64))) != 0;
  }
  return FALSE;
}

bool Curl_uint32_spbset_first(struct uint32_spbset *bset, uint32_t *pfirst)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t i;

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    for(i = 0; i < CURL_UINT32_SPBSET_CH_SLOTS; ++i) {
      if(chunk->slots[i]) {
        *pfirst = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
        return TRUE;
      }
    }
  }
  *pfirst = 0; /* give it a defined value even if it should not be used */
  return FALSE;
}

static bool uint32_spbset_chunk_first(struct uint32_spbset_chunk *chunk,
                                      uint32_t *pfirst)
{
  uint32_t i;
  for(i = 0; i < CURL_UINT32_SPBSET_CH_SLOTS; ++i) {
    if(chunk->slots[i]) {
      *pfirst = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
      return TRUE;
    }
  }
  *pfirst = UINT32_MAX; /* a value we cannot store */
  return FALSE;
}

static bool uint32_spbset_chunk_next(struct uint32_spbset_chunk *chunk,
                                     uint32_t last,
                                     uint32_t *pnext)
{
  if(chunk->offset <= last) {
    uint64_t x;
    uint32_t i = ((last - chunk->offset) / 64);
    if(i < CURL_UINT32_SPBSET_CH_SLOTS) {
      x = (chunk->slots[i] >> (last % 64));
      if(x) {
        /* more bits set, next is `last` + trailing0s of the shifted slot */
        *pnext = last + CURL_CTZ64(x);
        return TRUE;
      }
      /* no more bits set in the last slot, scan forward */
      for(i = i + 1; i < CURL_UINT32_SPBSET_CH_SLOTS; ++i) {
        if(chunk->slots[i]) {
          *pnext = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
          return TRUE;
        }
      }
    }
  }
  *pnext = UINT32_MAX;
  return FALSE;
}

bool Curl_uint32_spbset_next(struct uint32_spbset *bset, uint32_t last,
                             uint32_t *pnext)
{
  struct uint32_spbset_chunk *chunk;
  uint32_t last_offset;

  ++last; /* look for the next higher number */
  last_offset = (last & ~CURL_UINT32_SPBSET_CH_MASK);

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    if(chunk->offset >= last_offset) {
      break;
    }
  }

  if(chunk && (chunk->offset == last_offset)) {
    /* is there a number higher than last in this chunk? */
    if(uint32_spbset_chunk_next(chunk, last, pnext))
      return TRUE;
    /* not in this chunk */
    chunk = chunk->next;
  }
  /* look for the first in the "higher" chunks, if there are any. */
  while(chunk) {
    if(uint32_spbset_chunk_first(chunk, pnext))
      return TRUE;
    chunk = chunk->next;
  }
  *pnext = UINT32_MAX;
  return FALSE;
}
