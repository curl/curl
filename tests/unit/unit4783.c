/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Lennart Finke
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
#include "vauth/vauth.h"
#include "vauth/digest.h"

#if !defined(CURL_DISABLE_DIGEST_AUTH) && !defined(USE_WINDOWS_SSPI)
static void t4783_challenges(void)
{
  static const char * const invalid[] = {
    "realm=\"", "realm=\"abc", "realm=\"abc\\", "realm=\"abc\\\"",
    "realm=\"abc\r", "realm=\"abc\n", "extension=\"abc",
    "extension =\"abc", "realm=abc\""
  };
  char realm[2 * DIGEST_MAX_CONTENT_LENGTH + 32];
  char expected[DIGEST_MAX_CONTENT_LENGTH];
  char challenge[sizeof(realm) + 64];
  struct digestdata digest;
  CURLcode result;
  size_t i;
  size_t count;
  unsigned int order;
  unsigned int escaped;

  memset(&digest, 0, sizeof(digest));
  for(count = 511; count <= 513; count++) {
    for(i = 0; i < count; i++) {
      realm[2 * i] = '\\';
      realm[2 * i + 1] = 'a';
      expected[i] = 'a';
    }
    memcpy(realm + 2 * count, ", nonce=evil,", sizeof(", nonce=evil,"));
    memcpy(expected + count, ", nonce=evil,", sizeof(", nonce=evil,"));

    /* The injected nonce stays in the realm in either directive order. */
    for(order = 0; order < 2; order++) {
      curl_msnprintf(challenge, sizeof(challenge), order ?
                    "nonce=\"good\", realm=\"%s\", qop=\"auth\"" :
                    "realm=\"%s\", nonce=\"good\", qop=\"auth\"", realm);
      result = Curl_auth_decode_digest_http_message(challenge, &digest);
      fail_unless(result == CURLE_OK, "valid challenge rejected");
      fail_unless(digest.realm && !strcmp(digest.realm, expected),
                  "full realm");
      fail_unless(digest.nonce && !strcmp(digest.nonce, "good"), "real nonce");
      fail_unless(digest.qop && !strcmp(digest.qop, "auth"), "qop retained");
      Curl_auth_digest_cleanup(&digest);
    }
  }

  for(i = 0; i < CURL_ARRAYSIZE(invalid); i++) {
    for(order = 0; order < 2; order++) {
      curl_msnprintf(challenge, sizeof(challenge), order ?
                    "nonce=good, %s" : "%s, nonce=good", invalid[i]);
      result = Curl_auth_decode_digest_http_message(challenge, &digest);
      fail_unless(result == CURLE_BAD_CONTENT_ENCODING, "bad realm accepted");
      fail_if(digest.nonce || digest.realm, "partial challenge retained");
      Curl_auth_digest_cleanup(&digest);
    }
  }

  for(escaped = 0; escaped < 2; escaped++) {
    for(count = 1023; count <= 1024; count++) {
      char *p = realm;
      for(i = 0; i < count; i++) {
        if(escaped)
          *p++ = '\\';
        *p++ = 'a';
      }
      *p = 0;
      for(order = 0; order < 2; order++) {
        curl_msnprintf(challenge, sizeof(challenge), order ?
                      "nonce=good, realm=\"%s\", qop=auth" :
                      "realm=\"%s\", nonce=good, qop=auth", realm);
        result = Curl_auth_decode_digest_http_message(challenge, &digest);
        if(count == 1023) {
          fail_unless(result == CURLE_OK, "maximum realm rejected");
          fail_unless(digest.realm && strlen(digest.realm) == count,
                      "maximum realm truncated");
          fail_unless(digest.nonce && !strcmp(digest.nonce, "good"),
                      "nonce after maximum realm");
        }
        else {
          fail_unless(result == CURLE_BAD_CONTENT_ENCODING,
                      "oversized realm accepted");
          fail_if(digest.nonce || digest.realm, "partial challenge retained");
        }
        Curl_auth_digest_cleanup(&digest);
      }
    }
  }
}

static void t4783_combined(void)
{
  static const char * const suffixes[] = {
    "", " ", ",", ", \t", ", Negotiate", ", Negotiate ",
    ", Negotiate, Basic realm=\"other\"",
    ", Negotiate YWJjZA==",
    ", Basic realm=\"other\", nonce=\"other\"",
    ", X-Custom token==, nonce=\"other\"",
    ", extension=value"
  };
  char challenge[256];
  struct digestdata digest;
  CURLcode result;
  size_t i;

  memset(&digest, 0, sizeof(digest));
  for(i = 0; i < CURL_ARRAYSIZE(suffixes); i++) {
    curl_msnprintf(challenge, sizeof(challenge),
                  "realm=\"test\", nonce=\"good\"%s", suffixes[i]);
    result = Curl_auth_decode_digest_http_message(challenge, &digest);
    fail_unless(result == CURLE_OK, "combined challenge rejected");
    fail_unless(digest.nonce && !strcmp(digest.nonce, "good"), "Digest nonce");
    fail_unless(digest.realm && !strcmp(digest.realm, "test"), "Digest realm");
    Curl_auth_digest_cleanup(&digest);
  }
  result = Curl_auth_decode_digest_http_message(
    "realm=\"test\", Basic realm=\"other\", nonce=\"other\"", &digest);
  fail_unless(result == CURLE_BAD_CONTENT_ENCODING,
              "another challenge's nonce accepted for Digest");
  Curl_auth_digest_cleanup(&digest);
}
#endif

static CURLcode test_unit4783(const char *arg)
{
  UNITTEST_BEGIN(curl_global_init(CURL_GLOBAL_ALL))
#if !defined(CURL_DISABLE_DIGEST_AUTH) && !defined(USE_WINDOWS_SSPI)
  t4783_challenges();
  t4783_combined();
#endif
  UNITTEST_END(curl_global_cleanup())
}
