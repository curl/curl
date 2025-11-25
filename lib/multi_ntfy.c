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

#include "urldata.h"
#include "curl_trc.h"
#include "multihandle.h"
#include "multiif.h"
#include "multi_ntfy.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


struct mntfy_entry {
  uint32_t mid;
  uint32_t type;
};

#define CURL_MNTFY_CHUNK_SIZE   128

struct mntfy_chunk {
  struct mntfy_chunk *next;
  size_t r_offset;
  size_t w_offset;
  struct mntfy_entry entries[CURL_MNTFY_CHUNK_SIZE];
};

static struct mntfy_chunk *mnfty_chunk_create(void)
{
  return calloc(1, sizeof(struct mntfy_chunk));
}

static void mnfty_chunk_destroy(struct mntfy_chunk *chunk)
{
  free(chunk);
}

static void mnfty_chunk_reset(struct mntfy_chunk *chunk)
{
  memset(chunk, 0, sizeof(*chunk));
}

static bool mntfy_chunk_append(struct mntfy_chunk *chunk,
                               struct Curl_easy *data,
                               uint32_t type)
{
  struct mntfy_entry *e;

  if(chunk->w_offset >= CURL_MNTFY_CHUNK_SIZE)
    return FALSE;
  e = &chunk->entries[chunk->w_offset++];
  e->mid = data->mid;
  e->type = type;
  return TRUE;
}

static struct mntfy_chunk *mntfy_non_full_tail(struct curl_multi_ntfy *mntfy)
{
  struct mntfy_chunk *chunk;
  if(!mntfy->tail) {
    chunk = mnfty_chunk_create();
    if(!chunk)
      return NULL;
    DEBUGASSERT(!mntfy->head);
    mntfy->head = mntfy->tail = chunk;
    return chunk;
  }
  else if(mntfy->tail->w_offset < CURL_MNTFY_CHUNK_SIZE)
    return mntfy->tail;
  else { /* tail is full. */
    chunk = mnfty_chunk_create();
    if(!chunk)
      return NULL;
    DEBUGASSERT(mntfy->head);
    mntfy->tail->next = chunk;
    mntfy->tail = chunk;
    return chunk;
  }
}

static void mntfy_chunk_dispatch_all(struct Curl_multi *multi,
                                     struct mntfy_chunk *chunk)
{
  struct mntfy_entry *e;
  struct Curl_easy *data;

  if(multi->ntfy.ntfy_cb) {
    while((chunk->r_offset < chunk->w_offset) && !multi->ntfy.failure) {
      e = &chunk->entries[chunk->r_offset];
      data = e->mid ? Curl_multi_get_easy(multi, e->mid) : multi->admin;
      /* only when notification has not been disabled in the meantime */
      if(data && Curl_uint32_bset_contains(&multi->ntfy.enabled, e->type)) {
        /* this may cause new notifications to be added! */
        CURL_TRC_M(multi->admin, "[NTFY] dispatch %d to xfer %u",
                   e->type, e->mid);
        multi->ntfy.ntfy_cb(multi, e->type, data, multi->ntfy.ntfy_cb_data);
      }
      /* once dispatched, safe to increment */
      chunk->r_offset++;
    }
  }
  mnfty_chunk_reset(chunk);
}

void Curl_mntfy_init(struct Curl_multi *multi)
{
  memset(&multi->ntfy, 0, sizeof(multi->ntfy));
  Curl_uint32_bset_init(&multi->ntfy.enabled);
}

CURLMcode Curl_mntfy_resize(struct Curl_multi *multi)
{
  if(Curl_uint32_bset_resize(&multi->ntfy.enabled, CURLMNOTIFY_EASY_DONE + 1))
    return CURLM_OUT_OF_MEMORY;
  return CURLM_OK;
}

void Curl_mntfy_cleanup(struct Curl_multi *multi)
{
  while(multi->ntfy.head) {
    struct mntfy_chunk *chunk = multi->ntfy.head;
    multi->ntfy.head = chunk->next;
    mnfty_chunk_destroy(chunk);
  }
  multi->ntfy.tail = NULL;
  Curl_uint32_bset_destroy(&multi->ntfy.enabled);
}

CURLMcode Curl_mntfy_enable(struct Curl_multi *multi, unsigned int type)
{
  if(type > CURLMNOTIFY_EASY_DONE)
    return CURLM_UNKNOWN_OPTION;
  Curl_uint32_bset_add(&multi->ntfy.enabled, type);
  return CURLM_OK;
}

CURLMcode Curl_mntfy_disable(struct Curl_multi *multi, unsigned int type)
{
  if(type > CURLMNOTIFY_EASY_DONE)
    return CURLM_UNKNOWN_OPTION;
  Curl_uint32_bset_remove(&multi->ntfy.enabled, (uint32_t)type);
  return CURLM_OK;
}

void Curl_mntfy_add(struct Curl_easy *data, unsigned int type)
{
  struct Curl_multi *multi = data ? data->multi : NULL;
  if(multi && multi->ntfy.ntfy_cb && !multi->ntfy.failure &&
     Curl_uint32_bset_contains(&multi->ntfy.enabled, (uint32_t)type)) {
    /* append to list of outstanding notifications */
    struct mntfy_chunk *tail = mntfy_non_full_tail(&multi->ntfy);
  CURL_TRC_M(data, "[NTFY] add %d for xfer %u", type, data->mid);
    if(tail)
      mntfy_chunk_append(tail, data, (uint32_t)type);
    else
      multi->ntfy.failure = CURLM_OUT_OF_MEMORY;
  }
}

CURLMcode Curl_mntfy_dispatch_all(struct Curl_multi *multi)
{
  DEBUGASSERT(!multi->in_ntfy_callback);
  multi->in_ntfy_callback = TRUE;
  while(multi->ntfy.head && !multi->ntfy.failure) {
    struct mntfy_chunk *chunk = multi->ntfy.head;
    /* this may cause new notifications to be added! */
    mntfy_chunk_dispatch_all(multi, chunk);
    DEBUGASSERT(chunk->r_offset == chunk->w_offset);

    if(chunk == multi->ntfy.tail) /* last one, keep */
      break;
    DEBUGASSERT(chunk->next);
    DEBUGASSERT(multi->ntfy.head != multi->ntfy.tail);
    multi->ntfy.head = chunk->next;
    mnfty_chunk_destroy(chunk);
  }
  multi->in_ntfy_callback = FALSE;

  if(multi->ntfy.failure) {
    CURLMcode result = multi->ntfy.failure;
    multi->ntfy.failure = CURLM_OK; /* reset, once delivered */
    return result;
  }
  return CURLM_OK;
}
