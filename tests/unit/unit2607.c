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
#include "unitcheck.h"
#include "urldata.h"
#include "bufq.h"

/* Test ws_enc_mask_write(): payload pushed in random pieces into a
 * hard-limited bufq, with random drains in between, must come out
 * masked exactly as with a byte-by-byte reference, and the xor index
 * must only advance by the bytes the bufq accepted. */

#ifndef CURL_DISABLE_WEBSOCKETS

static unsigned int t2607_rand(unsigned int *seed)
{
  *seed = *seed * 1103515245U + 12345U;
  return (*seed >> 16) & 0x7fff;
}

static CURLcode test_unit2607(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static uint8_t pool[8192];
  static uint8_t piece[3000];
  static uint8_t drained[2048];
  unsigned int seed = 2607;
  unsigned int round;
  size_t i;

  for(i = 0; i < sizeof(pool); i++)
    pool[i] = (uint8_t)t2607_rand(&seed);

  for(round = 0; round < 300; round++) {
    struct bufq q;
    uint8_t mask[4];
    unsigned int xori0 = t2607_rand(&seed) & 3;
    unsigned int xori = xori0;
    size_t chunk_size = 1 + (t2607_rand(&seed) % 700);
    size_t max_chunks = 1 + (t2607_rand(&seed) % 3);
    size_t sent = 0;   /* bytes accepted by the bufq */
    size_t checked = 0; /* bytes read back and verified */
    unsigned int step;

    for(i = 0; i < 4; i++)
      mask[i] = (uint8_t)t2607_rand(&seed);
    Curl_bufq_init(&q, chunk_size, max_chunks);

    for(step = 0; step < 100; step++) {
      size_t len = t2607_rand(&seed) % sizeof(piece);
      size_t drain = t2607_rand(&seed) % sizeof(drained);
      size_t before = Curl_bufq_len(&q);
      bool full = Curl_bufq_is_full(&q);
      size_t nwritten, nread;
      CURLcode result;

      for(i = 0; i < len; i++)
        piece[i] = pool[(sent + i) % sizeof(pool)];
      result = ws_enc_mask_write(mask, &xori, piece, len, &q, &nwritten);
      if(full && len) {
        fail_unless(result == CURLE_AGAIN, "full bufq must return AGAIN");
        fail_unless(!nwritten, "full bufq must not take data");
      }
      else {
        fail_unless(result == CURLE_OK, "unexpected result");
        fail_unless(nwritten <= len, "wrote more than given");
        fail_unless(!len || nwritten, "no progress on non-full bufq");
      }
      fail_unless(Curl_bufq_len(&q) == before + nwritten,
                  "bufq length does not match nwritten");
      sent += nwritten;
      fail_unless(xori == ((xori0 + sent) & 3), "xor index out of step");

      result = Curl_bufq_read(&q, drained, drain, &nread);
      fail_unless(!result || result == CURLE_AGAIN, "read failed");
      for(i = 0; i < nread; i++) {
        size_t k = checked + i;
        uint8_t want = pool[k % sizeof(pool)] ^ mask[(xori0 + k) & 3];
        if(drained[i] != want) {
          /* report the first difference only */
          fail_unless(drained[i] == want,
                      "masked output differs from reference");
          break;
        }
      }
      checked += nread;
    }
    fail_unless(checked + Curl_bufq_len(&q) == sent, "lost data");
    Curl_bufq_free(&q);
  }

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit2607(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since WebSocket is disabled");
  UNITTEST_END_SIMPLE
}

#endif
