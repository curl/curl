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

static CURLcode test_unit3403(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  char *result = NULL;
  size_t olen = 0;
  CURLcode rc;

  /* ==================================================================
   * curl_easy_escape
   * ================================================================== */

  /* unreserved characters must pass through unencoded */
  result = curl_easy_escape(NULL, "azAZ09-._~", 0);
  abort_unless(result, "escape of unreserved chars must succeed");
  fail_unless(strcmp(result, "azAZ09-._~") == 0,
              "unreserved chars must not be percent-encoded");
  curl_free(result);

  /* space must become %20 */
  result = curl_easy_escape(NULL, " ", 0);
  abort_unless(result, "escape of space must succeed");
  fail_unless(strcmp(result, "%20") == 0, "space must encode to %20");
  curl_free(result);

  /* all common special chars get encoded */
  result = curl_easy_escape(NULL, "hello world!", 0);
  abort_unless(result, "escape of 'hello world!' must succeed");
  fail_unless(strcmp(result, "hello%20world%21") == 0,
              "space->%20 and !->%21");
  curl_free(result);

  /* high-byte value 0xFF */
  result = curl_easy_escape(NULL, "\xff", 1);
  abort_unless(result, "escape of 0xFF must succeed");
  fail_unless(strcmp(result, "%FF") == 0, "0xFF must encode to %FF");
  curl_free(result);

  /* empty string returns empty string, not NULL */
  result = curl_easy_escape(NULL, "", 0);
  abort_unless(result, "escape of empty string must succeed");
  fail_unless(strcmp(result, "") == 0, "escape of empty string must be empty");
  curl_free(result);

  /* explicit length overrides strlen — encode only 5 chars of a longer string */
  result = curl_easy_escape(NULL, "hello world", 5);
  abort_unless(result, "escape with explicit length must succeed");
  fail_unless(strcmp(result, "hello") == 0,
              "explicit length=5 must produce only 'hello'");
  curl_free(result);

  /* NULL string must return NULL */
  result = curl_easy_escape(NULL, NULL, 0);
  fail_unless(!result, "escape of NULL string must return NULL");

  /* negative length must return NULL */
  result = curl_easy_escape(NULL, "hello", -1);
  fail_unless(!result, "escape with negative length must return NULL");

  /* ==================================================================
   * curl_easy_unescape
   * ================================================================== */

  /* basic percent-decode */
  result = curl_easy_unescape(NULL, "%68%65%6c%6c%6f", 0, NULL);
  abort_unless(result, "unescape of %%68%%65%%6c%%6c%%6f must succeed");
  fail_unless(strcmp(result, "hello") == 0,
              "%%68%%65%%6c%%6c%%6f must decode to 'hello'");
  curl_free(result);

  /* mixed encoded and plain text */
  result = curl_easy_unescape(NULL, "hello%20world", 0, NULL);
  abort_unless(result, "unescape of 'hello%%20world' must succeed");
  fail_unless(strcmp(result, "hello world") == 0,
              "hello%%20world must decode to 'hello world'");
  curl_free(result);

  /* output length reported correctly */
  {
    int outlen = -1;
    result = curl_easy_unescape(NULL, "%41%42%43", 0, &outlen);
    abort_unless(result, "unescape of %%41%%42%%43 must succeed");
    fail_unless(strcmp(result, "ABC") == 0,
                "%%41%%42%%43 must decode to 'ABC'");
    fail_unless(outlen == 3, "output length must be 3");
    curl_free(result);
  }

  /* uppercase hex digits also work */
  result = curl_easy_unescape(NULL, "%2F", 0, NULL);
  abort_unless(result, "unescape of %%2F must succeed");
  fail_unless(strcmp(result, "/") == 0, "%%2F must decode to '/'");
  curl_free(result);

  /* a lone % that is not followed by two hex digits passes through */
  result = curl_easy_unescape(NULL, "100%", 0, NULL);
  abort_unless(result, "unescape of '100%%' must succeed");
  fail_unless(strcmp(result, "100%") == 0,
              "trailing lone %% must be kept as-is");
  curl_free(result);

  /* empty input */
  result = curl_easy_unescape(NULL, "", 0, NULL);
  abort_unless(result, "unescape of empty string must succeed");
  fail_unless(strcmp(result, "") == 0, "unescape of empty must be empty");
  curl_free(result);

  /* negative length must return NULL */
  result = curl_easy_unescape(NULL, "hello", -1, NULL);
  fail_unless(!result, "unescape with negative length must return NULL");

  /* ==================================================================
   * Curl_urldecode — internal decoder with ctrl-char rejection
   * ================================================================== */

  /* REJECT_NADA: accepts everything including control chars */
  rc = Curl_urldecode("%01%02", 0, &result, &olen, REJECT_NADA);
  fail_unless(rc == CURLE_OK, "REJECT_NADA must accept control chars");
  fail_unless(olen == 2, "decoded length must be 2");
  curl_free(result);

  /* REJECT_CTRL: rejects decoded bytes < 0x20 */
  rc = Curl_urldecode("%01", 0, &result, &olen, REJECT_CTRL);
  fail_unless(rc == CURLE_URL_MALFORMAT,
              "REJECT_CTRL must reject control byte 0x01");

  /* REJECT_CTRL: allows regular bytes */
  rc = Curl_urldecode("hello%20world", 0, &result, &olen, REJECT_CTRL);
  fail_unless(rc == CURLE_OK,
              "REJECT_CTRL must allow non-control encoded chars");
  fail_unless(olen == 11, "decoded length must be 11");
  fail_unless(strcmp(result, "hello world") == 0,
              "REJECT_CTRL decode of 'hello%%20world' must be 'hello world'");
  curl_free(result);

  /* REJECT_ZERO: rejects a decoded NUL byte */
  rc = Curl_urldecode("%00", 0, &result, &olen, REJECT_ZERO);
  fail_unless(rc == CURLE_URL_MALFORMAT,
              "REJECT_ZERO must reject encoded NUL byte");

  /* REJECT_ZERO: allows non-NUL bytes */
  rc = Curl_urldecode("ok", 0, &result, &olen, REJECT_ZERO);
  fail_unless(rc == CURLE_OK, "REJECT_ZERO must allow normal bytes");
  fail_unless(olen == 2, "decoded length of 'ok' must be 2");
  curl_free(result);

  /* ==================================================================
   * Curl_hexencode
   * ================================================================== */

  {
    const unsigned char src[] = {0x00, 0x0f, 0x10, 0xff, 0xab};
    unsigned char out[11]; /* 5 bytes * 2 hex chars + NUL */
    memset(out, 0xcc, sizeof(out));
    Curl_hexencode(src, sizeof(src), out, sizeof(out));
    fail_unless(strcmp((char *)out, "000f10ffab") == 0,
                "Curl_hexencode must produce lowercase hex");
    fail_unless(out[10] == '\0', "Curl_hexencode must NUL-terminate");
  }

  /* single byte */
  {
    const unsigned char src[] = {0xbe};
    unsigned char out[3];
    Curl_hexencode(src, 1, out, sizeof(out));
    fail_unless(strcmp((char *)out, "be") == 0,
                "Curl_hexencode single byte 0xBE must be 'be'");
  }

  /* ==================================================================
   * Curl_hexbyte
   * ================================================================== */

  {
    unsigned char dest[2];
    Curl_hexbyte(dest, 0x00);
    fail_unless(dest[0] == '0' && dest[1] == '0',
                "Curl_hexbyte(0x00) must produce '00'");

    Curl_hexbyte(dest, 0xFF);
    fail_unless(dest[0] == 'F' && dest[1] == 'F',
                "Curl_hexbyte(0xFF) must produce 'FF' (uppercase)");

    Curl_hexbyte(dest, 0x1A);
    fail_unless(dest[0] == '1' && dest[1] == 'A',
                "Curl_hexbyte(0x1A) must produce '1A'");

    Curl_hexbyte(dest, 0xa3);
    fail_unless(dest[0] == 'A' && dest[1] == '3',
                "Curl_hexbyte(0xa3) must produce 'A3'");
  }

  UNITTEST_END_SIMPLE
}
