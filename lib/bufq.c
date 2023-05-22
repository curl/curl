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
#include "bufq.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static bool chunk_is_empty(const struct buf_chunk *chunk)
{
  return chunk->r_offset >= chunk->w_offset;
}

static bool chunk_is_full(const struct buf_chunk *chunk)
{
  return chunk->w_offset >= chunk->dlen;
}

static size_t chunk_len(const struct buf_chunk *chunk)
{
  return chunk->w_offset - chunk->r_offset;
}

static size_t chunk_space(const struct buf_chunk *chunk)
{
  return chunk->dlen - chunk->w_offset;
}

static void chunk_reset(struct buf_chunk *chunk)
{
  chunk->next = NULL;
  chunk->r_offset = chunk->w_offset = 0;
}

static size_t chunk_append(struct buf_chunk *chunk,
                           const unsigned char *buf, size_t len)
{
  unsigned char *p = &chunk->x.data[chunk->w_offset];
  size_t n = chunk->dlen - chunk->w_offset;
  DEBUGASSERT(chunk->dlen >= chunk->w_offset);
  if(n) {
    n = CURLMIN(n, len);
    memcpy(p, buf, n);
    chunk->w_offset += n;
  }
  return n;
}

static size_t chunk_read(struct buf_chunk *chunk,
                         unsigned char *buf, size_t len)
{
  unsigned char *p = &chunk->x.data[chunk->r_offset];
  size_t n = chunk->w_offset - chunk->r_offset;
  DEBUGASSERT(chunk->w_offset >= chunk->r_offset);
  if(!n) {
    return 0;
  }
  else if(n <= len) {
    memcpy(buf, p, n);
    chunk->r_offset = chunk->w_offset = 0;
    return n;
  }
  else {
    memcpy(buf, p, len);
    chunk->r_offset += len;
    return len;
  }
}

static ssize_t chunk_slurpn(struct buf_chunk *chunk, size_t max_len,
                            Curl_bufq_reader *reader,
                            void *reader_ctx, CURLcode *err)
{
  unsigned char *p = &chunk->x.data[chunk->w_offset];
  size_t n = chunk->dlen - chunk->w_offset; /* free amount */
  ssize_t nread;

  DEBUGASSERT(chunk->dlen >= chunk->w_offset);
  if(!n) {
    *err = CURLE_AGAIN;
    return -1;
  }
  if(max_len && n > max_len)
    n = max_len;
  nread = reader(reader_ctx, p, n, err);
  if(nread > 0) {
    DEBUGASSERT((size_t)nread <= n);
    chunk->w_offset += nread;
  }
  return nread;
}

static void chunk_peek(const struct buf_chunk *chunk,
                       const unsigned char **pbuf, size_t *plen)
{
  DEBUGASSERT(chunk->w_offset >= chunk->r_offset);
  *pbuf = &chunk->x.data[chunk->r_offset];
  *plen = chunk->w_offset - chunk->r_offset;
}

static void chunk_peek_at(const struct buf_chunk *chunk, size_t offset,
                          const unsigned char **pbuf, size_t *plen)
{
  offset += chunk->r_offset;
  DEBUGASSERT(chunk->w_offset >= offset);
  *pbuf = &chunk->x.data[offset];
  *plen = chunk->w_offset - offset;
}

static size_t chunk_skip(struct buf_chunk *chunk, size_t amount)
{
  size_t n = chunk->w_offset - chunk->r_offset;
  DEBUGASSERT(chunk->w_offset >= chunk->r_offset);
  if(n) {
    n = CURLMIN(n, amount);
    chunk->r_offset += n;
    if(chunk->r_offset == chunk->w_offset)
      chunk->r_offset = chunk->w_offset = 0;
  }
  return n;
}

static void chunk_shift(struct buf_chunk *chunk)
{
  if(chunk->r_offset) {
    if(!chunk_is_empty(chunk)) {
      size_t n = chunk->w_offset - chunk->r_offset;
      memmove(chunk->x.data, chunk->x.data + chunk->r_offset, n);
      chunk->w_offset -= chunk->r_offset;
      chunk->r_offset = 0;
    }
    else {
      chunk->r_offset = chunk->w_offset = 0;
    }
  }
}

static void chunk_list_free(struct buf_chunk **anchor)
{
  struct buf_chunk *chunk;
  while(*anchor) {
    chunk = *anchor;
    *anchor = chunk->next;
    free(chunk);
  }
}



void Curl_bufcp_init(struct bufc_pool *pool,
                     size_t chunk_size, size_t spare_max)
{
  DEBUGASSERT(chunk_size > 0);
  DEBUGASSERT(spare_max > 0);
  memset(pool, 0, sizeof(*pool));
  pool->chunk_size = chunk_size;
  pool->spare_max = spare_max;
}

static CURLcode bufcp_take(struct bufc_pool *pool,
                           struct buf_chunk **pchunk)
{
  struct buf_chunk *chunk = NULL;

  if(pool->spare) {
    chunk = pool->spare;
    pool->spare = chunk->next;
    --pool->spare_count;
    chunk_reset(chunk);
    *pchunk = chunk;
    return CURLE_OK;
  }

  chunk = calloc(1, sizeof(*chunk) + pool->chunk_size);
  if(!chunk) {
    *pchunk = NULL;
    return CURLE_OUT_OF_MEMORY;
  }
  chunk->dlen = pool->chunk_size;
  *pchunk = chunk;
  return CURLE_OK;
}

static void bufcp_put(struct bufc_pool *pool,
                      struct buf_chunk *chunk)
{
  if(pool->spare_count >= pool->spare_max) {
    free(chunk);
  }
  else {
    chunk_reset(chunk);
    chunk->next = pool->spare;
    pool->spare = chunk;
    ++pool->spare_count;
  }
}

void Curl_bufcp_free(struct bufc_pool *pool)
{
  chunk_list_free(&pool->spare);
  pool->spare_count = 0;
}

static void bufq_init(struct bufq *q, struct bufc_pool *pool,
                      size_t chunk_size, size_t max_chunks, int opts)
{
  DEBUGASSERT(chunk_size > 0);
  DEBUGASSERT(max_chunks > 0);
  memset(q, 0, sizeof(*q));
  q->chunk_size = chunk_size;
  q->max_chunks = max_chunks;
  q->pool = pool;
  q->opts = opts;
}

void Curl_bufq_init2(struct bufq *q, size_t chunk_size, size_t max_chunks,
                     int opts)
{
  bufq_init(q, NULL, chunk_size, max_chunks, opts);
}

void Curl_bufq_init(struct bufq *q, size_t chunk_size, size_t max_chunks)
{
  bufq_init(q, NULL, chunk_size, max_chunks, BUFQ_OPT_NONE);
}

void Curl_bufq_initp(struct bufq *q, struct bufc_pool *pool,
                     size_t max_chunks, int opts)
{
  bufq_init(q, pool, pool->chunk_size, max_chunks, opts);
}

void Curl_bufq_free(struct bufq *q)
{
  chunk_list_free(&q->head);
  chunk_list_free(&q->spare);
  q->tail = NULL;
  q->chunk_count = 0;
}

void Curl_bufq_reset(struct bufq *q)
{
  struct buf_chunk *chunk;
  while(q->head) {
    chunk = q->head;
    q->head = chunk->next;
    chunk->next = q->spare;
    q->spare = chunk;
  }
  q->tail = NULL;
}

size_t Curl_bufq_len(const struct bufq *q)
{
  const struct buf_chunk *chunk = q->head;
  size_t len = 0;
  while(chunk) {
    len += chunk_len(chunk);
    chunk = chunk->next;
  }
  return len;
}

size_t Curl_bufq_space(const struct bufq *q)
{
  size_t space = 0;
  if(q->tail)
    space += chunk_space(q->tail);
  if(q->spare) {
    struct buf_chunk *chunk = q->spare;
    while(chunk) {
      space += chunk->dlen;
      chunk = chunk->next;
    }
  }
  if(q->chunk_count < q->max_chunks) {
    space += (q->max_chunks - q->chunk_count) * q->chunk_size;
  }
  return space;
}

bool Curl_bufq_is_empty(const struct bufq *q)
{
  return !q->head || chunk_is_empty(q->head);
}

bool Curl_bufq_is_full(const struct bufq *q)
{
  if(!q->tail || q->spare)
    return FALSE;
  if(q->chunk_count < q->max_chunks)
    return FALSE;
  if(q->chunk_count > q->max_chunks)
    return TRUE;
  /* we have no spares and cannot make more, is the tail full? */
  return chunk_is_full(q->tail);
}

static struct buf_chunk *get_spare(struct bufq *q)
{
  struct buf_chunk *chunk = NULL;

  if(q->spare) {
    chunk = q->spare;
    q->spare = chunk->next;
    chunk_reset(chunk);
    return chunk;
  }

  if(q->chunk_count >= q->max_chunks && (!(q->opts & BUFQ_OPT_SOFT_LIMIT)))
    return NULL;

  if(q->pool) {
    if(bufcp_take(q->pool, &chunk))
      return NULL;
    ++q->chunk_count;
    return chunk;
  }
  else {
    chunk = calloc(1, sizeof(*chunk) + q->chunk_size);
    if(!chunk)
      return NULL;
    chunk->dlen = q->chunk_size;
    ++q->chunk_count;
    return chunk;
  }
}

static void prune_head(struct bufq *q)
{
  struct buf_chunk *chunk;

  while(q->head && chunk_is_empty(q->head)) {
    chunk = q->head;
    q->head = chunk->next;
    if(q->tail == chunk)
      q->tail = q->head;
    if(q->pool) {
      bufcp_put(q->pool, chunk);
      --q->chunk_count;
    }
    else if((q->chunk_count > q->max_chunks) ||
       (q->opts & BUFQ_OPT_NO_SPARES)) {
      /* SOFT_LIMIT allowed us more than max. free spares until
       * we are at max again. Or free them if we are configured
       * to not use spares. */
      free(chunk);
      --q->chunk_count;
    }
    else {
      chunk->next = q->spare;
      q->spare = chunk;
    }
  }
}

static struct buf_chunk *get_non_full_tail(struct bufq *q)
{
  struct buf_chunk *chunk;

  if(q->tail && !chunk_is_full(q->tail))
    return q->tail;
  chunk = get_spare(q);
  if(chunk) {
    /* new tail, and possibly new head */
    if(q->tail) {
      q->tail->next = chunk;
      q->tail = chunk;
    }
    else {
      DEBUGASSERT(!q->head);
      q->head = q->tail = chunk;
    }
  }
  return chunk;
}

ssize_t Curl_bufq_write(struct bufq *q,
                        const unsigned char *buf, size_t len,
                        CURLcode *err)
{
  struct buf_chunk *tail;
  ssize_t nwritten = 0;
  size_t n;

  DEBUGASSERT(q->max_chunks > 0);
  while(len) {
    tail = get_non_full_tail(q);
    if(!tail) {
      if(q->chunk_count < q->max_chunks) {
        *err = CURLE_OUT_OF_MEMORY;
        return -1;
      }
      break;
    }
    n = chunk_append(tail, buf, len);
    DEBUGASSERT(n);
    nwritten += n;
    buf += n;
    len -= n;
  }
  if(nwritten == 0 && len) {
    *err = CURLE_AGAIN;
    return -1;
  }
  *err = CURLE_OK;
  return nwritten;
}

ssize_t Curl_bufq_read(struct bufq *q, unsigned char *buf, size_t len,
                       CURLcode *err)
{
  ssize_t nread = 0;
  size_t n;

  *err = CURLE_OK;
  while(len && q->head) {
    n = chunk_read(q->head, buf, len);
    if(n) {
      nread += n;
      buf += n;
      len -= n;
    }
    prune_head(q);
  }
  if(nread == 0) {
    *err = CURLE_AGAIN;
    return -1;
  }
  return nread;
}

bool Curl_bufq_peek(struct bufq *q,
                    const unsigned char **pbuf, size_t *plen)
{
  if(q->head && chunk_is_empty(q->head)) {
    prune_head(q);
  }
  if(q->head && !chunk_is_empty(q->head)) {
    chunk_peek(q->head, pbuf, plen);
    return TRUE;
  }
  *pbuf = NULL;
  *plen = 0;
  return FALSE;
}

bool Curl_bufq_peek_at(struct bufq *q, size_t offset,
                       const unsigned char **pbuf, size_t *plen)
{
  struct buf_chunk *c = q->head;
  size_t clen;

  while(c) {
    clen = chunk_len(c);
    if(!clen)
      break;
    if(offset >= clen) {
      offset -= clen;
      c = c->next;
      continue;
    }
    chunk_peek_at(c, offset, pbuf, plen);
    return TRUE;
  }
  *pbuf = NULL;
  *plen = 0;
  return FALSE;
}

void Curl_bufq_skip(struct bufq *q, size_t amount)
{
  size_t n;

  while(amount && q->head) {
    n = chunk_skip(q->head, amount);
    amount -= n;
    prune_head(q);
  }
}

void Curl_bufq_skip_and_shift(struct bufq *q, size_t amount)
{
  Curl_bufq_skip(q, amount);
  if(q->tail)
    chunk_shift(q->tail);
}

ssize_t Curl_bufq_pass(struct bufq *q, Curl_bufq_writer *writer,
                       void *writer_ctx, CURLcode *err)
{
  const unsigned char *buf;
  size_t blen;
  ssize_t nwritten = 0;

  while(Curl_bufq_peek(q, &buf, &blen)) {
    ssize_t chunk_written;

    chunk_written = writer(writer_ctx, buf, blen, err);
    if(chunk_written < 0) {
      if(!nwritten || *err != CURLE_AGAIN) {
        /* blocked on first write or real error, fail */
        nwritten = -1;
      }
      break;
    }
    Curl_bufq_skip(q, (size_t)chunk_written);
    nwritten += chunk_written;
  }
  return nwritten;
}

ssize_t Curl_bufq_write_pass(struct bufq *q,
                             const unsigned char *buf, size_t len,
                             Curl_bufq_writer *writer, void *writer_ctx,
                             CURLcode *err)
{
  ssize_t nwritten = 0, n;

  *err = CURLE_OK;
  while(len) {
    if(Curl_bufq_is_full(q)) {
      /* try to make room in case we are full */
      n = Curl_bufq_pass(q, writer, writer_ctx, err);
      if(n < 0) {
        if(*err != CURLE_AGAIN) {
          /* real error, fail */
          return -1;
        }
        /* would block */
      }
    }

    /* Add whatever is remaining now to bufq */
    n = Curl_bufq_write(q, buf, len, err);
    if(n < 0) {
      if(*err != CURLE_AGAIN) {
        /* real error, fail */
        return -1;
      }
      /* no room in bufq, bail out */
      goto out;
    }
    /* Maybe only part of `data` has been added, continue to loop */
    buf += (size_t)n;
    len -= (size_t)n;
    nwritten += (size_t)n;
  }

out:
  return nwritten;
}

ssize_t Curl_bufq_sipn(struct bufq *q, size_t max_len,
                       Curl_bufq_reader *reader, void *reader_ctx,
                       CURLcode *err)
{
  struct buf_chunk *tail = NULL;
  ssize_t nread;

  *err = CURLE_AGAIN;
  tail = get_non_full_tail(q);
  if(!tail) {
    if(q->chunk_count < q->max_chunks) {
      *err = CURLE_OUT_OF_MEMORY;
      return -1;
    }
    /* full, blocked */
    *err = CURLE_AGAIN;
    return -1;
  }

  nread = chunk_slurpn(tail, max_len, reader, reader_ctx, err);
  if(nread < 0) {
    return -1;
  }
  else if(nread == 0) {
    /* eof */
    *err = CURLE_OK;
  }
  return nread;
}

/**
 * Read up to `max_len` bytes and append it to the end of the buffer queue.
 * if `max_len` is 0, no limit is imposed and the call behaves exactly
 * the same as `Curl_bufq_slurp()`.
 * Returns the total amount of buf read (may be 0) or -1 on other
 * reader errors.
 * Note that even in case of a -1 chunks may have been read and
 * the buffer queue will have different length than before.
 */
static ssize_t bufq_slurpn(struct bufq *q, size_t max_len,
                           Curl_bufq_reader *reader, void *reader_ctx,
                           CURLcode *err)
{
  ssize_t nread = 0, n;

  *err = CURLE_AGAIN;
  while(1) {

    n = Curl_bufq_sipn(q, max_len, reader, reader_ctx, err);
    if(n < 0) {
      if(!nread || *err != CURLE_AGAIN) {
        /* blocked on first read or real error, fail */
        nread = -1;
      }
      else
        *err = CURLE_OK;
      break;
    }
    else if(n == 0) {
      /* eof */
      *err = CURLE_OK;
      break;
    }
    nread += (size_t)n;
    if(max_len) {
      DEBUGASSERT((size_t)n <= max_len);
      max_len -= (size_t)n;
      if(!max_len)
        break;
    }
    /* give up slurping when we get less bytes than we asked for */
    if(q->tail && !chunk_is_full(q->tail))
      break;
  }
  return nread;
}

ssize_t Curl_bufq_slurp(struct bufq *q, Curl_bufq_reader *reader,
                        void *reader_ctx, CURLcode *err)
{
  return bufq_slurpn(q, 0, reader, reader_ctx, err);
}
