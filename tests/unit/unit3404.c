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
#include "curl_endian.h"

static CURLcode test_unit3404(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  /* ==================================================================
   * Curl_read16_le — little-endian 16-bit reader
   * ================================================================== */

  /* 0x0102 stored little-endian: low byte first */
  {
    const unsigned char buf[] = {0x02, 0x01};
    fail_unless(Curl_read16_le(buf) == 0x0102,
                "Curl_read16_le({0x02,0x01}) must return 0x0102");
  }

  /* zero */
  {
    const unsigned char buf[] = {0x00, 0x00};
    fail_unless(Curl_read16_le(buf) == 0x0000,
                "Curl_read16_le all-zero must return 0");
  }

  /* max value 0xFFFF */
  {
    const unsigned char buf[] = {0xFF, 0xFF};
    fail_unless(Curl_read16_le(buf) == 0xFFFF,
                "Curl_read16_le({0xFF,0xFF}) must return 0xFFFF");
  }

  /* byte order check: low nibble in first byte, high nibble in second */
  {
    const unsigned char buf[] = {0xCD, 0xAB};
    fail_unless(Curl_read16_le(buf) == 0xABCD,
                "Curl_read16_le({0xCD,0xAB}) must return 0xABCD");
  }

  /* 0x0100 — only high byte set */
  {
    const unsigned char buf[] = {0x00, 0x01};
    fail_unless(Curl_read16_le(buf) == 0x0100,
                "Curl_read16_le({0x00,0x01}) must return 0x0100");
  }

  /* ==================================================================
   * Curl_read32_le — little-endian 32-bit reader
   * ================================================================== */

  /* 0x01020304 little-endian: lowest byte first */
  {
    const unsigned char buf[] = {0x04, 0x03, 0x02, 0x01};
    fail_unless(Curl_read32_le(buf) == 0x01020304U,
                "Curl_read32_le({0x04,0x03,0x02,0x01}) must return 0x01020304");
  }

  /* zero */
  {
    const unsigned char buf[] = {0x00, 0x00, 0x00, 0x00};
    fail_unless(Curl_read32_le(buf) == 0x00000000U,
                "Curl_read32_le all-zero must return 0");
  }

  /* max value 0xFFFFFFFF */
  {
    const unsigned char buf[] = {0xFF, 0xFF, 0xFF, 0xFF};
    fail_unless(Curl_read32_le(buf) == 0xFFFFFFFFU,
                "Curl_read32_le all-0xFF must return 0xFFFFFFFF");
  }

  /* only highest byte set: 0x01000000 */
  {
    const unsigned char buf[] = {0x00, 0x00, 0x00, 0x01};
    fail_unless(Curl_read32_le(buf) == 0x01000000U,
                "Curl_read32_le({0,0,0,1}) must return 0x01000000");
  }

  /* only lowest byte set: 0x00000001 */
  {
    const unsigned char buf[] = {0x01, 0x00, 0x00, 0x00};
    fail_unless(Curl_read32_le(buf) == 0x00000001U,
                "Curl_read32_le({1,0,0,0}) must return 0x00000001");
  }

  /* known value 0xDEADBEEF little-endian */
  {
    const unsigned char buf[] = {0xEF, 0xBE, 0xAD, 0xDE};
    fail_unless(Curl_read32_le(buf) == 0xDEADBEEFU,
                "Curl_read32_le(DEADBEEF LE) must return 0xDEADBEEF");
  }

  /* ==================================================================
   * Curl_read16_be — big-endian 16-bit reader
   * ================================================================== */

  /* 0x0102 stored big-endian: high byte first */
  {
    const unsigned char buf[] = {0x01, 0x02};
    fail_unless(Curl_read16_be(buf) == 0x0102,
                "Curl_read16_be({0x01,0x02}) must return 0x0102");
  }

  /* zero */
  {
    const unsigned char buf[] = {0x00, 0x00};
    fail_unless(Curl_read16_be(buf) == 0x0000,
                "Curl_read16_be all-zero must return 0");
  }

  /* max value 0xFFFF */
  {
    const unsigned char buf[] = {0xFF, 0xFF};
    fail_unless(Curl_read16_be(buf) == 0xFFFF,
                "Curl_read16_be({0xFF,0xFF}) must return 0xFFFF");
  }

  /* byte order check: high nibble in first byte */
  {
    const unsigned char buf[] = {0xAB, 0xCD};
    fail_unless(Curl_read16_be(buf) == 0xABCD,
                "Curl_read16_be({0xAB,0xCD}) must return 0xABCD");
  }

  /* 0x0100 big-endian */
  {
    const unsigned char buf[] = {0x01, 0x00};
    fail_unless(Curl_read16_be(buf) == 0x0100,
                "Curl_read16_be({0x01,0x00}) must return 0x0100");
  }

  /* ==================================================================
   * Cross-check: LE and BE must differ for asymmetric inputs
   * ================================================================== */
  {
    const unsigned char buf[] = {0x12, 0x34};
    unsigned short le = Curl_read16_le(buf);
    unsigned short be = Curl_read16_be(buf);
    fail_unless(le == 0x3412,
                "Curl_read16_le({0x12,0x34}) must return 0x3412");
    fail_unless(be == 0x1234,
                "Curl_read16_be({0x12,0x34}) must return 0x1234");
    fail_unless(le != be,
                "LE and BE of an asymmetric buffer must differ");
  }

  UNITTEST_END_SIMPLE
}
