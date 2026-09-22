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
#include "escape.h"

/* Surround each input and expected output with 'a' and 'z' padding. Keep
   explicit lengths so embedded zero bytes are part of the test data.
   Rejection bits select REJECT_CTRL (1) and REJECT_ZERO (2). */
#define U3307_CASE(prefix, input, expected, suffix, rejected) \
  { prefix, input, sizeof(input) - 1, expected, sizeof(expected) - 1, \
    suffix, rejected }

static CURLcode test_unit3307(const char *arg)
{
  UNITTEST_BEGIN(curl_global_init(CURL_GLOBAL_ALL))
  static const struct {
    size_t prefix;
    const char *input;
    size_t input_len;
    const char *expected;
    size_t expected_len;
    size_t suffix;
    unsigned int rejected;
  } cases[] = {
    /* Scalar tails, complete vectors, and the long literal fast path. */
    U3307_CASE(0, "", "", 0, 0),
    U3307_CASE(31, "", "", 0, 0),
    U3307_CASE(32, "", "", 0, 0),
    U3307_CASE(33, "", "", 0, 0),
    U3307_CASE(127, "", "", 0, 0),
    U3307_CASE(128, "", "", 0, 0),
    U3307_CASE(160, "", "", 0, 0),
    U3307_CASE(160, "%41", "A", 40, 0),
    /* A percent in each lookahead block prevents the bulk copy. */
    U3307_CASE(32, "%41", "A", 128, 0),
    U3307_CASE(64, "%41", "A", 96, 0),
    U3307_CASE(96, "%41", "A", 64, 0),
    /* Escapes crossing the 16-byte lane and 32-byte input boundaries. */
    U3307_CASE(14, "%41", "A", 32, 0),
    U3307_CASE(15, "%41", "A", 32, 0),
    U3307_CASE(16, "%41", "A", 32, 0),
    U3307_CASE(29, "%41", "A", 0, 0),
    U3307_CASE(30, "%41", "A", 32, 0),
    U3307_CASE(31, "%41", "A", 32, 0),
    U3307_CASE(0, "%41%41%41%41%41%41%41%41%41%41%41%41",
               "AAAAAAAAAAAA", 0, 0),
    U3307_CASE(0, "%20%2F%3a%40%aF%Ff", " /:@\257\377", 64, 0),
    /* Malformed and incomplete escapes must be preserved verbatim. */
    U3307_CASE(0, "%GG%4Z%Z4%%41%4%41", "%GG%4Z%Z4%A%4A", 40, 0),
    U3307_CASE(0, "%\200f%f\377", "%\200f%f\377", 40, 0),
    U3307_CASE(30, "%%", "%%", 0, 0),
    U3307_CASE(30, "%4", "%4", 0, 0),
    U3307_CASE(31, "%", "%", 0, 0),
    U3307_CASE(128, "%", "%", 0, 0),
    /* Raw bytes in literal vectors and in the bulk copy path. */
    U3307_CASE(0, "\200\377", "\200\377", 30, 0),
    U3307_CASE(20, "\0", "\0", 11, 3),
    U3307_CASE(20, "\037", "\037", 11, 1),
    U3307_CASE(100, "\0", "\0", 40, 3),
    U3307_CASE(100, "\037", "\037", 40, 1),
    U3307_CASE(160, "\0", "\0", 40, 3),
    /* Rejection applies to decoded bytes and surviving literal bytes. */
    U3307_CASE(0, "%00", "\0", 32, 3),
    U3307_CASE(0, "%01%1f", "\001\037", 32, 1),
    U3307_CASE(0, "%41\0", "A\0", 32, 3),
    U3307_CASE(0, "%41\037", "A\037", 32, 1),
    U3307_CASE(30, "%00", "\0", 32, 3),
    U3307_CASE(31, "%00", "\0", 32, 3),
    U3307_CASE(160, "%00", "\0", 32, 3)
  };
  static const enum urlreject modes[] = {
    REJECT_NADA, REJECT_CTRL, REJECT_ZERO
  };
  size_t i;

  /* The normal dispatcher exercises SIMD where supported, and the same
     expectations also test the scalar implementation on other hosts. */
  for(i = 0; i < CURL_ARRAYSIZE(cases); i++) {
    size_t input_len = cases[i].prefix + cases[i].input_len + cases[i].suffix;
    size_t expected_len =
      cases[i].prefix + cases[i].expected_len + cases[i].suffix;
    char *encoded;
    char expected[256];
    size_t m;

    abort_unless(expected_len <= sizeof(expected), "expected buffer size");
    encoded = curlx_malloc(input_len + 1);
    abort_unless(encoded, "input allocation");
    memset(encoded, 'a', cases[i].prefix);
    memcpy(encoded + cases[i].prefix, cases[i].input, cases[i].input_len);
    memset(encoded + cases[i].prefix + cases[i].input_len,
           'z', cases[i].suffix);
    encoded[input_len] = 0;
    memset(expected, 'a', cases[i].prefix);
    memcpy(expected + cases[i].prefix, cases[i].expected,
           cases[i].expected_len);
    memset(expected + cases[i].prefix + cases[i].expected_len,
           'z', cases[i].suffix);

    for(m = 0; m < CURL_ARRAYSIZE(modes); m++) {
      char *decoded = NULL;
      size_t output_len = 0;
      int failures_before = unitfail;
      unsigned int reject_bit = m ? 1U << (m - 1) : 0;
      CURLcode expected_result = (cases[i].rejected & reject_bit) ?
        CURLE_URL_MALFORMAT : CURLE_OK;
      CURLcode result = Curl_urldecode(encoded, input_len, &decoded,
                                      &output_len, modes[m]);

      fail_unless(result == expected_result, "decode result");
      if(!result) {
        fail_unless(decoded, "decoded output");
        fail_unless(output_len == expected_len, "decoded length");
        if(decoded && output_len == expected_len) {
          fail_unless(!memcmp(decoded, expected, expected_len),
                      "decoded bytes");
          fail_unless(!decoded[output_len], "output terminator");
        }
      }
      else
        fail_unless(!decoded, "output freed on rejection");
      if(unitfail != failures_before)
        curl_mfprintf(stderr, "case %zu, reject mode %d\n", i, (int)modes[m]);
      curlx_free(decoded);
    }
    curlx_free(encoded);
  }
  UNITTEST_END(curl_global_cleanup())
}

#undef U3307_CASE
