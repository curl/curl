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
#include "curlcheck.h"

#include "urldata.h"
#include "bufq.h"
#include "curl_trc.h"

static CURLcode unit_setup(void)
{
  CURLcode res = CURLE_OK;
  return res;
}

static void unit_stop(void)
{
}

static const char *tail_err(struct bufq *q)
{
  struct buf_chunk *chunk;

  if(!q->tail) {
    return q->head ? "tail is NULL, but head is not" : NULL;
  }

  chunk = q->head;
  while(chunk) {
    if(chunk == q->tail) {
      if(chunk->next) {
        return "tail points to queue, but not at the end";
      }
      return NULL;
    }
    chunk = chunk->next;
  }
  return "tail not part of queue";
}

static void dump_bufq(struct bufq *q, const char *msg)
{
  struct buf_chunk *chunk;
  const char *terr;
  size_t n;

  fprintf(stderr, "bufq[chunk_size=%zu, max_chunks=%zu] %s\n",
          q->chunk_size, q->max_chunks, msg);
  fprintf(stderr, "- queue[\n");
  chunk = q->head;
  while(chunk) {
    fprintf(stderr, "    chunk[len=%zu, roff=%zu, woff=%zu]\n",
            chunk->dlen, chunk->r_offset, chunk->w_offset);
    chunk = chunk->next;
  }
  fprintf(stderr, "  ]\n");
  terr = tail_err(q);
  fprintf(stderr, "- tail: %s\n", terr ? terr : "ok");
  n = 0;
  chunk = q->spare;
  while(chunk) {
    ++n;
    chunk = chunk->next;
  }
  fprintf(stderr, "- chunks: %zu\n", q->chunk_count);
  fprintf(stderr, "- spares: %zu\n", n);
}

static unsigned char test_data[32*1024];

static void check_bufq(size_t pool_spares,
                       size_t chunk_size, size_t max_chunks,
                       size_t wsize, size_t rsize, int opts)
{
  struct bufq q;
  struct bufc_pool pool;
  size_t max_len = chunk_size * max_chunks;
  CURLcode result;
  ssize_t n, i;
  size_t nwritten, nread;

  if(pool_spares > 0) {
    Curl_bufcp_init(&pool, chunk_size, pool_spares);
    Curl_bufq_initp(&q, &pool, max_chunks, opts);
  }
  else {
    Curl_bufq_init2(&q, chunk_size, max_chunks, opts);
  }

  fail_unless(q.chunk_size == chunk_size, "chunk_size init wrong");
  fail_unless(q.max_chunks == max_chunks, "max_chunks init wrong");
  fail_unless(q.head == NULL, "init: head not NULL");
  fail_unless(q.tail == NULL, "init: tail not NULL");
  fail_unless(q.spare == NULL, "init: spare not NULL");
  fail_unless(Curl_bufq_len(&q) == 0, "init: bufq length != 0");

  n = Curl_bufq_write(&q, test_data, wsize, &result);
  fail_unless(n >= 0, "write: negative size returned");
  fail_unless((size_t)n <= wsize, "write: wrong size returned");
  fail_unless(result == CURLE_OK, "write: wrong result returned");

  /* write empty bufq full */
  nwritten = 0;
  Curl_bufq_reset(&q);
  while(!Curl_bufq_is_full(&q)) {
    n = Curl_bufq_write(&q, test_data, wsize, &result);
    if(n >= 0) {
      nwritten += (size_t)n;
    }
    else if(result != CURLE_AGAIN) {
      fail_unless(result == CURLE_AGAIN, "write-loop: unexpected result");
      break;
    }
  }
  if(nwritten != max_len) {
    fprintf(stderr, "%zu bytes written, but max_len=%zu\n",
            nwritten, max_len);
    dump_bufq(&q, "after writing full");
    fail_if(TRUE, "write: bufq full but nwritten wrong");
  }

  /* read full bufq empty */
  nread = 0;
  while(!Curl_bufq_is_empty(&q)) {
    n = Curl_bufq_read(&q, test_data, rsize, &result);
    if(n >= 0) {
      nread += (size_t)n;
    }
    else if(result != CURLE_AGAIN) {
      fail_unless(result == CURLE_AGAIN, "read-loop: unexpected result");
      break;
    }
  }
  if(nread != max_len) {
    fprintf(stderr, "%zu bytes read, but max_len=%zu\n",
            nwritten, max_len);
    dump_bufq(&q, "after reading empty");
    fail_if(TRUE, "read: bufq empty but nread wrong");
  }
  if(q.tail) {
    dump_bufq(&q, "after reading empty");
    fail_if(TRUE, "read empty, but tail is not NULL");
  }

  for(i = 0; i < 1000; ++i) {
    n = Curl_bufq_write(&q, test_data, wsize, &result);
    if(n < 0 && result != CURLE_AGAIN) {
      fail_unless(result == CURLE_AGAIN, "rw-loop: unexpected write result");
      break;
    }
    n = Curl_bufq_read(&q, test_data, rsize, &result);
    if(n < 0 && result != CURLE_AGAIN) {
      fail_unless(result == CURLE_AGAIN, "rw-loop: unexpected read result");
      break;
    }
  }

  /* Test SOFT_LIMIT option */
  Curl_bufq_free(&q);
  Curl_bufq_init2(&q, chunk_size, max_chunks, (opts|BUFQ_OPT_SOFT_LIMIT));
  nwritten = 0;
  while(!Curl_bufq_is_full(&q)) {
    n = Curl_bufq_write(&q, test_data, wsize, &result);
    if(n < 0 || (size_t)n != wsize) {
      fail_unless(n > 0 && (size_t)n == wsize, "write should be complete");
      break;
    }
    nwritten += (size_t)n;
  }
  if(nwritten < max_len) {
    fprintf(stderr, "%zu bytes written, but max_len=%zu\n",
            nwritten, max_len);
    dump_bufq(&q, "after writing full");
    fail_if(TRUE, "write: bufq full but nwritten wrong");
  }
  /* do one more write on a full bufq, should work */
  n = Curl_bufq_write(&q, test_data, wsize, &result);
  fail_unless(n > 0 && (size_t)n == wsize, "write should be complete");
  nwritten += (size_t)n;
  /* see that we get all out again */
  nread = 0;
  while(!Curl_bufq_is_empty(&q)) {
    n = Curl_bufq_read(&q, test_data, rsize, &result);
    if(n <= 0) {
      fail_unless(n > 0, "read-loop: unexpected fail");
      break;
    }
    nread += (size_t)n;
  }
  fail_unless(nread == nwritten, "did not get the same out as put in");

  /* CHECK bufq_unwrite: write a string repeatedly into the second chunk.
   * bufq_unwrite() 1 byte. Read strings again and check for content.
   * We had a bug that unwrite used the head chunk instead of tail, which
   * did corrupt the read values. */
  if(TRUE) {
    const unsigned char buf[] = "0123456789--";
    size_t roffset;
    Curl_bufq_reset(&q);
    while(Curl_bufq_len(&q) < chunk_size) {
      n = Curl_bufq_write(&q, buf, sizeof(buf), &result);
      fail_unless(n > 0 && (size_t)n == sizeof(buf), "write incomplete");
      if(result)
        break;
    }
    result = Curl_bufq_unwrite(&q, 1);
    roffset = 0;
    while(!Curl_bufq_is_empty(&q)) {
      unsigned char rbuf[sizeof(buf)];
      n = Curl_bufq_read(&q, rbuf, sizeof(rbuf), &result);
      fail_unless(n > 0, "read should work");
      if(result)
        break;
      if(n != sizeof(rbuf)) {
        fail_unless(Curl_bufq_is_empty(&q), "should be last read");
      }
      if(memcmp(buf, rbuf, n)) {
        fprintf(stderr, "at offset %zu expected '%.*s', got '%.*s'\n",
                roffset, (int)n, buf, (int)n, rbuf);
        fail("read buf content wrong");
      }
      roffset += n;
    }
    Curl_bufq_reset(&q);
  }

  dump_bufq(&q, "at end of test");
  Curl_bufq_free(&q);
  if(pool_spares > 0)
    Curl_bufcp_free(&pool);
}

UNITTEST_START
  struct bufq q;
  ssize_t n;
  CURLcode result;
  unsigned char buf[16*1024];

  Curl_bufq_init(&q, 8*1024, 12);
  n = Curl_bufq_read(&q, buf, 128, &result);
  fail_unless(n < 0 && result == CURLE_AGAIN, "read empty fail");
  Curl_bufq_free(&q);

  check_bufq(0, 1024, 4, 128, 128, BUFQ_OPT_NONE);
  check_bufq(0, 1024, 4, 129, 127, BUFQ_OPT_NONE);
  check_bufq(0, 1024, 4, 2000, 16000, BUFQ_OPT_NONE);
  check_bufq(0, 1024, 4, 16000, 3000, BUFQ_OPT_NONE);

  check_bufq(0, 8000, 10, 1234, 1234, BUFQ_OPT_NONE);
  check_bufq(0, 8000, 10, 8*1024, 4*1024, BUFQ_OPT_NONE);

  check_bufq(0, 1024, 4, 128, 128, BUFQ_OPT_NO_SPARES);
  check_bufq(0, 1024, 4, 129, 127, BUFQ_OPT_NO_SPARES);
  check_bufq(0, 1024, 4, 2000, 16000, BUFQ_OPT_NO_SPARES);
  check_bufq(0, 1024, 4, 16000, 3000, BUFQ_OPT_NO_SPARES);

  check_bufq(8, 1024, 4, 128, 128, BUFQ_OPT_NONE);
  check_bufq(8, 8000, 10, 1234, 1234, BUFQ_OPT_NONE);
  check_bufq(8, 1024, 4, 129, 127, BUFQ_OPT_NO_SPARES);

UNITTEST_STOP
