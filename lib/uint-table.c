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

#include "uint-table.h"

#ifdef DEBUGBUILD
#define CURL_UINT32_TBL_MAGIC  0x62757473
#endif

/* Clear the table, making it empty. */
UNITTEST void Curl_uint32_tbl_clear(struct uint32_tbl *tbl);

void Curl_uint32_tbl_init(struct uint32_tbl *tbl,
                          Curl_uint32_tbl_entry_dtor *entry_dtor)
{
  memset(tbl, 0, sizeof(*tbl));
  tbl->entry_dtor = entry_dtor;
  tbl->last_key_added = UINT32_MAX;
#ifdef DEBUGBUILD
  tbl->init = CURL_UINT32_TBL_MAGIC;
#endif
}

static void uint32_tbl_clear_rows(struct uint32_tbl *tbl,
                                  uint32_t from,
                                  uint32_t upto_excluding)
{
  uint32_t i, end;

  end = CURLMIN(upto_excluding, tbl->nrows);
  for(i = from; i < end; ++i) {
    if(tbl->rows[i]) {
      if(tbl->entry_dtor)
        tbl->entry_dtor(i, tbl->rows[i]);
      tbl->rows[i] = NULL;
      tbl->nentries--;
    }
  }
}

CURLcode Curl_uint32_tbl_resize(struct uint32_tbl *tbl, uint32_t nrows)
{
  /* we use `tbl->nrows + 1` during iteration, want that to work */
  DEBUGASSERT(tbl->init == CURL_UINT32_TBL_MAGIC);
  if(!nrows)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(nrows != tbl->nrows) {
    void **rows = curlx_calloc(nrows, sizeof(void *));
    if(!rows)
      return CURLE_OUT_OF_MEMORY;
    if(tbl->rows) {
      memcpy(rows, tbl->rows, (CURLMIN(nrows, tbl->nrows) * sizeof(void *)));
      if(nrows < tbl->nrows)
        uint32_tbl_clear_rows(tbl, nrows, tbl->nrows);
      curlx_free(tbl->rows);
    }
    tbl->rows = rows;
    tbl->nrows = nrows;
  }
  return CURLE_OK;
}

void Curl_uint32_tbl_destroy(struct uint32_tbl *tbl)
{
  DEBUGASSERT(tbl->init == CURL_UINT32_TBL_MAGIC);
  Curl_uint32_tbl_clear(tbl);
  curlx_free(tbl->rows);
  memset(tbl, 0, sizeof(*tbl));
}

UNITTEST void Curl_uint32_tbl_clear(struct uint32_tbl *tbl)
{
  DEBUGASSERT(tbl->init == CURL_UINT32_TBL_MAGIC);
  uint32_tbl_clear_rows(tbl, 0, tbl->nrows);
  DEBUGASSERT(!tbl->nentries);
  tbl->last_key_added = UINT32_MAX;
}

uint32_t Curl_uint32_tbl_capacity(struct uint32_tbl *tbl)
{
  return tbl->nrows;
}

uint32_t Curl_uint32_tbl_count(struct uint32_tbl *tbl)
{
  return tbl->nentries;
}

void *Curl_uint32_tbl_get(struct uint32_tbl *tbl, uint32_t key)
{
  return (key < tbl->nrows) ? tbl->rows[key] : NULL;
}

bool Curl_uint32_tbl_add(struct uint32_tbl *tbl, void *entry, uint32_t *pkey)
{
  uint32_t key, start_pos;

  DEBUGASSERT(tbl->init == CURL_UINT32_TBL_MAGIC);
  if(!entry || !pkey)
    return FALSE;
  *pkey = UINT32_MAX;
  if(tbl->nentries == tbl->nrows)  /* full */
    return FALSE;

  start_pos = CURLMIN(tbl->last_key_added, tbl->nrows) + 1;
  for(key = start_pos; key < tbl->nrows; ++key) {
    if(!tbl->rows[key]) {
      tbl->rows[key] = entry;
      tbl->nentries++;
      tbl->last_key_added = key;
      *pkey = key;
      return TRUE;
    }
  }
  /* no free entry at or above tbl->maybe_next_key, wrap around */
  for(key = 0; key < start_pos; ++key) {
    if(!tbl->rows[key]) {
      tbl->rows[key] = entry;
      tbl->nentries++;
      tbl->last_key_added = key;
      *pkey = key;
      return TRUE;
    }
  }
  /* Did not find any free row? Should not happen */
  DEBUGASSERT(0);
  return FALSE;
}

void Curl_uint32_tbl_remove(struct uint32_tbl *tbl, uint32_t key)
{
  uint32_tbl_clear_rows(tbl, key, key + 1);
}

bool Curl_uint32_tbl_contains(struct uint32_tbl *tbl, uint32_t key)
{
  return (key < tbl->nrows) ? !!tbl->rows[key] : FALSE;
}

static bool uint32_tbl_next_at(struct uint32_tbl *tbl, uint32_t key,
                               uint32_t *pkey, void **pentry)
{
  for(; key < tbl->nrows; ++key) {
    if(tbl->rows[key]) {
      *pkey = key;
      *pentry = tbl->rows[key];
      return TRUE;
    }
  }
  *pkey = UINT32_MAX;  /* always invalid */
  *pentry = NULL;
  return FALSE;
}

bool Curl_uint32_tbl_first(struct uint32_tbl *tbl,
                           uint32_t *pkey, void **pentry)
{
  if(!pkey || !pentry)
    return FALSE;
  if(tbl->nentries && uint32_tbl_next_at(tbl, 0, pkey, pentry))
    return TRUE;
  DEBUGASSERT(!tbl->nentries);
  *pkey = UINT32_MAX;  /* always invalid */
  *pentry = NULL;
  return FALSE;
}

bool Curl_uint32_tbl_next(struct uint32_tbl *tbl, uint32_t last_key,
                          uint32_t *pkey, void **pentry)
{
  if(!pkey || !pentry)
    return FALSE;
  if(uint32_tbl_next_at(tbl, last_key + 1, pkey, pentry))
    return TRUE;
  *pkey = UINT32_MAX;  /* always invalid */
  *pentry = NULL;
  return FALSE;
}
