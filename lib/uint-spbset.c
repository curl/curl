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

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef DEBUGBUILD
#define CURL_UINT_SPBSET_MAGIC  0x70737362
#endif

/* Clear the bitset, making it empty. */
UNITTEST void Curl_uint_spbset_clear(struct uint_spbset *bset);

void Curl_uint_spbset_init(struct uint_spbset *bset)
{
  memset(bset, 0, sizeof(*bset));
#ifdef DEBUGBUILD
  bset->init = CURL_UINT_SPBSET_MAGIC;
#endif
}

void Curl_uint_spbset_destroy(struct uint_spbset *bset)
{
  DEBUGASSERT(bset->init == CURL_UINT_SPBSET_MAGIC);
  Curl_uint_spbset_clear(bset);
}

unsigned int Curl_uint_spbset_count(struct uint_spbset *bset)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i, n = 0;

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    for(i = 0; i < CURL_UINT_SPBSET_CH_SLOTS; ++i) {
      if(chunk->slots[i])
        n += CURL_POPCOUNT64(chunk->slots[i]);
    }
  }
  return n;
}

bool Curl_uint_spbset_empty(struct uint_spbset *bset)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i;

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    for(i = 0; i < CURL_UINT_SPBSET_CH_SLOTS; ++i) {
      if(chunk->slots[i])
        return FALSE;
    }
  }
  return TRUE;
}

UNITTEST void Curl_uint_spbset_clear(struct uint_spbset *bset)
{
  struct uint_spbset_chunk *next, *chunk;

  for(chunk = bset->head.next; chunk; chunk = next) {
    next = chunk->next;
    free(chunk);
  }
  memset(&bset->head, 0, sizeof(bset->head));
}


static struct uint_spbset_chunk *
uint_spbset_get_chunk(struct uint_spbset *bset, unsigned int i, bool grow)
{
  struct uint_spbset_chunk *chunk, **panchor = NULL;
  unsigned int i_offset = (i & ~CURL_UINT_SPBSET_CH_MASK);

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
  chunk = calloc(1, sizeof(*chunk));
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


bool Curl_uint_spbset_add(struct uint_spbset *bset, unsigned int i)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i_chunk;

  chunk = uint_spbset_get_chunk(bset, i, TRUE);
  if(!chunk)
    return FALSE;

  DEBUGASSERT(i >= chunk->offset);
  i_chunk = (i - chunk->offset);
  DEBUGASSERT((i_chunk / 64) < CURL_UINT_SPBSET_CH_SLOTS);
  chunk->slots[(i_chunk / 64)] |= ((curl_uint64_t)1 << (i_chunk % 64));
  return TRUE;
}


void Curl_uint_spbset_remove(struct uint_spbset *bset, unsigned int i)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i_chunk;

  chunk = uint_spbset_get_chunk(bset, i, FALSE);
  if(chunk) {
    DEBUGASSERT(i >= chunk->offset);
    i_chunk = (i - chunk->offset);
    DEBUGASSERT((i_chunk / 64) < CURL_UINT_SPBSET_CH_SLOTS);
    chunk->slots[(i_chunk / 64)] &= ~((curl_uint64_t)1 << (i_chunk % 64));
  }
}


bool Curl_uint_spbset_contains(struct uint_spbset *bset, unsigned int i)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i_chunk;

  chunk = uint_spbset_get_chunk(bset, i, FALSE);
  if(chunk) {
    DEBUGASSERT(i >= chunk->offset);
    i_chunk = (i - chunk->offset);
    DEBUGASSERT((i_chunk / 64) < CURL_UINT_SPBSET_CH_SLOTS);
    return (chunk->slots[i_chunk / 64] &
            ((curl_uint64_t)1 << (i_chunk % 64))) != 0;
  }
  return FALSE;
}

bool Curl_uint_spbset_first(struct uint_spbset *bset, unsigned int *pfirst)
{
  struct uint_spbset_chunk *chunk;
  unsigned int i;

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    for(i = 0; i < CURL_UINT_SPBSET_CH_SLOTS; ++i) {
      if(chunk->slots[i]) {
        *pfirst = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
        return TRUE;
      }
    }
  }
  *pfirst = 0; /* give it a defined value even if it should not be used */
  return FALSE;
}


static bool uint_spbset_chunk_first(struct uint_spbset_chunk *chunk,
                                    unsigned int *pfirst)
{
  unsigned int i;
  for(i = 0; i < CURL_UINT_SPBSET_CH_SLOTS; ++i) {
    if(chunk->slots[i]) {
      *pfirst = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
      return TRUE;
    }
  }
  *pfirst = UINT_MAX; /* a value we cannot store */
  return FALSE;
}


static bool uint_spbset_chunk_next(struct uint_spbset_chunk *chunk,
                                   unsigned int last,
                                   unsigned int *pnext)
{
  if(chunk->offset <= last) {
    curl_uint64_t x;
    unsigned int i = ((last - chunk->offset) / 64);
    if(i < CURL_UINT_SPBSET_CH_SLOTS) {
      x = (chunk->slots[i] >> (last % 64));
      if(x) {
        /* more bits set, next is `last` + trailing0s of the shifted slot */
        *pnext = last + CURL_CTZ64(x);
        return TRUE;
      }
      /* no more bits set in the last slot, scan forward */
      for(i = i + 1; i < CURL_UINT_SPBSET_CH_SLOTS; ++i) {
        if(chunk->slots[i]) {
          *pnext = chunk->offset + ((i * 64) + CURL_CTZ64(chunk->slots[i]));
          return TRUE;
        }
      }
    }
  }
  *pnext = UINT_MAX;
  return FALSE;
}

bool Curl_uint_spbset_next(struct uint_spbset *bset, unsigned int last,
                           unsigned int *pnext)
{
  struct uint_spbset_chunk *chunk;
  unsigned int last_offset;

  ++last; /* look for the next higher number */
  last_offset = (last & ~CURL_UINT_SPBSET_CH_MASK);

  for(chunk = &bset->head; chunk; chunk = chunk->next) {
    if(chunk->offset >= last_offset) {
      break;
    }
  }

  if(chunk && (chunk->offset == last_offset)) {
    /* is there a number higher than last in this chunk? */
    if(uint_spbset_chunk_next(chunk, last, pnext))
      return TRUE;
    /* not in this chunk */
    chunk = chunk->next;
  }
  /* look for the first in the "higher" chunks, if there are any. */
  while(chunk) {
    if(uint_spbset_chunk_first(chunk, pnext))
      return TRUE;
    chunk = chunk->next;
  }
  *pnext = UINT_MAX;
  return FALSE;
}
