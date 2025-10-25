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

#include "http_aws_sigv4.h"
#include "curl_sha256.h"
#include "escape.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
static void sha256_to_hex(char *dst, unsigned char *sha)
{
  Curl_hexencode(sha, CURL_SHA256_DIGEST_LENGTH,
                 (unsigned char *)dst, 2 * CURL_SHA256_DIGEST_LENGTH + 1);
}
#endif

static CURLcode test_unit1985(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)

  /* Test basic string-to-sign format */
  const char *timestamp = "20150830T123600Z";
  const char *credential_scope = "20150830/us-east-1/service/aws4_request";
  const char *canonical_request = "GET\n/\n\nhost:example.amazonaws.com\n\n"
    "host\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  unsigned char sha_hash[CURL_SHA256_DIGEST_LENGTH];
  char sha_hex[2 * CURL_SHA256_DIGEST_LENGTH + 1];
  char string_to_sign[512];
  CURLcode result;

  /* Calculate SHA256 of canonical request */
  result = Curl_sha256it(sha_hash, (const unsigned char *)canonical_request,
                         strlen(canonical_request));
  fail_unless(!result, "SHA256 calculation failed");

  sha256_to_hex(sha_hex, sha_hash);

  /* Build string to sign */
  curl_msnprintf(string_to_sign, sizeof(string_to_sign),
                 "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                 timestamp, credential_scope, sha_hex);

  /* Verify format starts with AWS4-HMAC-SHA256 */
  fail_unless(!strncmp(string_to_sign, "AWS4-HMAC-SHA256\n", 17),
              "String-to-sign format incorrect");

  /* Verify contains timestamp */
  fail_unless(strstr(string_to_sign, timestamp) != NULL,
              "String-to-sign missing timestamp");

  /* Verify contains credential scope */
  fail_unless(strstr(string_to_sign, credential_scope) != NULL,
              "String-to-sign missing credential scope");

  /* Verify contains SHA256 hash */
  fail_unless(strstr(string_to_sign, sha_hex) != NULL,
              "String-to-sign missing canonical request hash");

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
