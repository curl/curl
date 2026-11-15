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
#include "curl_md5.h"
#include "curl_sha256.h"
#include "curl_sha512_256.h"

static CURLcode t1601_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

static CURLcode test_unit1601(const char *arg)
{
  UNITTEST_BEGIN(t1601_setup())

#ifdef CURL_HAVE_MD5
  {
    uint8_t output[CURL_MD5_DIGEST_LEN];

    Curl_md5it(output, STRCONST("1"));
    verify_memory(output, "\xc4\xca\x42\x38\xa0\xb9\x23\x82\x0d\xcc\x50\x9a"
                  "\x6f\x75\x84\x9b", CURL_MD5_DIGEST_LEN);

    Curl_md5it(output, STRCONST("hello-you-fool"));
    verify_memory(output, "\x88\x67\x0b\x6d\x5d\x74\x2f\xad\xa5\xcd\xf9\xb6"
                  "\x82\x87\x5f\x22", CURL_MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    uint8_t output[CURL_SHA256_DIGEST_LENGTH];

    Curl_sha256it(output, STRCONST("1"));
    verify_memory(output, "\x6b\x86\xb2\x73\xff\x34\xfc\xe1\x9d\x6b\x80\x4e"
                  "\xff\x5a\x3f\x57\x47\xad\xa4\xea\xa2\x2f\x1d\x49\xc0\x1e"
                  "\x52\xdd\xb7\x87\x5b\x4b", CURL_SHA256_DIGEST_LENGTH);

    Curl_sha256it(output, STRCONST("hello-you-fool"));
    verify_memory(output, "\xcb\xb1\x6a\x8a\xb9\xcb\xb9\x35\xa8\xcb\xa0\x2e"
                  "\x28\xc0\x26\x30\xd1\x19\x9c\x1f\x02\x17\xf4\x7c\x96\x20"
                  "\xf3\xef\xe8\x27\x15\xae", CURL_SHA256_DIGEST_LENGTH);
  }
#endif
#ifdef CURL_HAVE_SHA512_256
  {
    uint8_t output[CURL_SHA512_256_DIGEST_LENGTH];

    Curl_sha512_256it(output, STRCONST("1"));
    verify_memory(output, "\x18\xd2\x75\x66\xbd\x1a\xc6\x6b\x23\x32\xd8\xc5"
                  "\x4a\xd4\x3f\x7b\xb2\x20\x79\xc9\x06\xd0\x5f\x49\x1f\x3f"
                  "\x07\xa2\x8d\x5c\x69\x90", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST("hello-you-fool"));
    verify_memory(output, "\xaf\x6f\xb4\xb0\x13\x9b\xee\x13\xd1\x95\x3c\xb8"
                  "\xc7\xcd\x5b\x19\xf9\xcd\xcd\x21\xef\xdf\xa7\x42\x5c\x07"
                  "\x13\xea\xcc\x1a\x39\x76", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST("abc"));
    verify_memory(output, "\x53\x04\x8E\x26\x81\x94\x1E\xF9\x9B\x2E\x29\xB7"
                  "\x6B\x4C\x7D\xAB\xE4\xC2\xD0\xC6\x34\xFC\x6D\x46\xE0\xE2"
                  "\xF1\x31\x07\xE7\xAF\x23", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST(""));  /* empty, zero size input */
    verify_memory(output, "\xc6\x72\xb8\xd1\xef\x56\xed\x28\xab\x87\xc3\x62"
                  "\x2c\x51\x14\x06\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74\x98\xd0"
                  "\xc0\x1e\xce\xf0\x96\x7a", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST(
                      "abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA"
                      "abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA"));
    verify_memory(output, "\xad\xe9\x5d\x55\x3b\x9e\x45\x69\xdb\x53\xa4\x04"
                  "\x92\xe7\x87\x94\xff\xc9\x98\x5f\x93\x03\x86\x45\xe1\x97"
                  "\x17\x72\x7c\xbc\x31\x15", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST(
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/long/long/long/long/long/long/long"
                      "/long/long/long/long/path?with%20some=parameters"));
    verify_memory(output, "\xbc\xab\xc6\x2c\x0a\x22\xd5\xcb\xac\xac\xe9\x25"
                  "\xcf\xce\xaa\xaf\x0e\xa1\xed\x42\x46\x8a\xe2\x01\xee\x2f"
                  "\xdb\x39\x75\x47\x73\xf1", CURL_SHA512_256_DIGEST_LENGTH);

    Curl_sha512_256it(output, STRCONST("Simple string."));
    verify_memory(output, "\xde\xcb\x3c\x81\x65\x4b\xa0\xf5\xf0\x45\x6b\x7e"
                  "\x61\xf5\x0d\xf5\x38\xa4\xfc\xb1\x8a\x95\xff\x59\xbc\x04"
                  "\x82\xcf\x23\xb2\x32\x56", CURL_SHA512_256_DIGEST_LENGTH);
  }
#endif /* CURL_HAVE_SHA512_256 */

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

#ifdef CURL_HAVE_MD5
  {
    uint8_t output[CURL_MD5_DIGEST_LEN];

    Curl_hmacit(&Curl_HMAC_MD5,
                STRCONST("Pa55worD"), STRCONST("1"), output);
    verify_memory(output, "\xd1\x29\x75\x43\x58\xdc\xab\x78\xdf\xcd\x7f\x2b"
                  "\x29\x31\x13\x37", CURL_MD5_DIGEST_LEN);

    Curl_hmacit(&Curl_HMAC_MD5,
                STRCONST("Pa55worD"), STRCONST("hello-you-fool"), output);
    verify_memory(output, "\x75\xf1\xa7\xb9\xf5\x40\xe5\xa4\x98\x83\x9f\x64"
                  "\x5a\x27\x6d\xd0", CURL_MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    uint8_t output[CURL_SHA256_DIGEST_LENGTH];

    Curl_hmacit(&Curl_HMAC_SHA256,
                STRCONST("Pa55worD"), STRCONST("1"), output);
    verify_memory(output, "\x8c\x9d\x74\x0f\x32\xf7\xbb\xb7\xec\xe0\x07\x7e"
                  "\xc1\x8e\x1f\xdb\x17\x02\x6e\xaf\x9c\xcf\x76\x3d\x26\x88"
                  "\x56\x6d\xc8\x07\xbf\x59", CURL_SHA256_DIGEST_LENGTH);

    Curl_hmacit(&Curl_HMAC_SHA256,
                STRCONST("Pa55worD"), STRCONST("hello-you-fool"), output);
    verify_memory(output, "\xe4\x81\x63\x53\xab\xc6\x8c\x34\xd4\xa8\xe5\xc8"
                  "\xf3\x1d\x12\xbd\xaf\xd6\x58\x73\x11\xe9\xe6\xf9\x93\x2e"
                  "\x0a\xba\x69\x49\x63\x8c", CURL_SHA256_DIGEST_LENGTH);
  }
#endif
#endif /* feature using HMAC */

  UNITTEST_END(curl_global_cleanup())
}
