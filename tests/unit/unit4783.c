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
#include "curlx/strparse.h"

#ifndef CURL_DISABLE_DIGEST_AUTH
static void t4783_pairs(void)
{
  static const size_t lengths[] = { 0, 511, 512, 513, 1023, 1024 };
  static const char * const invalid[] = {
    "realm=\"", "realm=\"abc", "realm=\"abc\\", "realm=\"abc\\\"",
    "realm=\"abc\r", "realm=\"abc\n"
  };
  char pairbuf[2 * DIGEST_MAX_CONTENT_LENGTH + 32];
  char content[DIGEST_MAX_CONTENT_LENGTH];
  struct Curl_str name;
  const char *end;
  size_t i;
  unsigned int escaped;

  for(escaped = 0; escaped < 2; escaped++) {
    for(i = 0; i < CURL_ARRAYSIZE(lengths); i++) {
      size_t j;
      char *p = pairbuf;
      bool parsed;
      memcpy(p, "realm=\"", 7);
      p += 7;
      for(j = 0; j < lengths[i]; j++) {
        if(escaped)
          *p++ = '\\';
        *p++ = 'a';
      }
      memcpy(p, "\", nonce=good", sizeof("\", nonce=good"));
      parsed = Curl_auth_digest_get_pair(pairbuf, &name, content, &end);
      fail_unless(parsed == (lengths[i] < sizeof(content)), "value limit");
      if(parsed) {
        fail_unless(strlen(content) == lengths[i], "decoded length");
        fail_unless(!strcmp(end, ", nonce=good"), "closing quote consumed");
      }
    }
  }
  for(i = 0; i < CURL_ARRAYSIZE(invalid); i++)
    fail_if(Curl_auth_digest_get_pair(invalid[i], &name, content, &end),
            "unterminated quoted value accepted");
}

#ifndef USE_WINDOWS_SSPI
static void t4783_challenges(void)
{
  static const char * const invalid[] = {
    "nonce=good, realm=\"abc", "nonce=good, realm=\"abc\\"
  };
  char realm[2 * DIGEST_MAX_CONTENT_LENGTH + 32];
  char expected[DIGEST_MAX_CONTENT_LENGTH];
  char challenge[sizeof(realm) + 64];
  struct digestdata digest;
  CURLcode result;
  size_t i;

  memset(&digest, 0, sizeof(digest));
  for(i = 0; i < 512; i++) {
    realm[2 * i] = '\\';
    realm[2 * i + 1] = 'a';
    expected[i] = 'a';
  }
  memcpy(realm + 1024, ",nonce=evil,", sizeof(",nonce=evil,"));
  memcpy(expected + 512, ",nonce=evil,", sizeof(",nonce=evil,"));

  /* The injected nonce stays in the realm in either directive order. */
  for(i = 0; i < 2; i++) {
    curl_msnprintf(challenge, sizeof(challenge), i ?
                  "nonce=\"good\", realm=\"%s\", qop=\"auth\"" :
                  "realm=\"%s\", nonce=\"good\", qop=\"auth\"", realm);
    result = Curl_auth_decode_digest_http_message(challenge, &digest);
    fail_unless(result == CURLE_OK, "valid challenge rejected");
    fail_unless(digest.realm && !strcmp(digest.realm, expected), "full realm");
    fail_unless(digest.nonce && !strcmp(digest.nonce, "good"), "real nonce");
    fail_unless(digest.qop && !strcmp(digest.qop, "auth"), "qop retained");
    Curl_auth_digest_cleanup(&digest);
  }

  /* A nonce parsed before a malformed realm must not make it acceptable. */
  for(i = 0; i < CURL_ARRAYSIZE(invalid); i++) {
    result = Curl_auth_decode_digest_http_message(invalid[i], &digest);
    fail_unless(result == CURLE_BAD_CONTENT_ENCODING, "bad realm accepted");
    fail_if(digest.nonce, "partial challenge retained");
    Curl_auth_digest_cleanup(&digest);
  }
  memset(realm, 'a', DIGEST_MAX_CONTENT_LENGTH);
  realm[DIGEST_MAX_CONTENT_LENGTH] = 0;
  curl_msnprintf(challenge, sizeof(challenge),
                "nonce=good, realm=\"%s\", qop=auth", realm);
  result = Curl_auth_decode_digest_http_message(challenge, &digest);
  fail_unless(result == CURLE_BAD_CONTENT_ENCODING,
              "oversized realm accepted");
  fail_if(digest.nonce, "partial challenge retained");
  Curl_auth_digest_cleanup(&digest);
}
#endif
#endif

static CURLcode test_unit4783(const char *arg)
{
  UNITTEST_BEGIN(curl_global_init(CURL_GLOBAL_ALL))
#ifndef CURL_DISABLE_DIGEST_AUTH
  t4783_pairs();
#ifndef USE_WINDOWS_SSPI
  t4783_challenges();
#endif
#endif
  UNITTEST_END(curl_global_cleanup())
}
