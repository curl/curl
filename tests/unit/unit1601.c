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
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    unsigned char output[MD5_DIGEST_LEN];

    Curl_md5it(output, (const unsigned char *)string1, strlen(string1));

    verify_memory(output, "\xc4\xca\x42\x38\xa0\xb9\x23\x82\x0d\xcc\x50\x9a"
                  "\x6f\x75\x84\x9b", MD5_DIGEST_LEN);

    Curl_md5it(output, (const unsigned char *)string2, strlen(string2));

    verify_memory(output, "\x88\x67\x0b\x6d\x5d\x74\x2f\xad\xa5\xcd\xf9\xb6"
                  "\x82\x87\x5f\x22", MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    unsigned char output[CURL_SHA256_DIGEST_LENGTH];

    Curl_sha256it(output, (const unsigned char *)string1, strlen(string1));

    verify_memory(output, "\x6b\x86\xb2\x73\xff\x34\xfc\xe1\x9d\x6b\x80\x4e"
                  "\xff\x5a\x3f\x57\x47\xad\xa4\xea\xa2\x2f\x1d\x49\xc0\x1e"
                  "\x52\xdd\xb7\x87\x5b\x4b", CURL_SHA256_DIGEST_LENGTH);

    Curl_sha256it(output, (const unsigned char *)string2, strlen(string2));

    verify_memory(output, "\xcb\xb1\x6a\x8a\xb9\xcb\xb9\x35\xa8\xcb\xa0\x2e"
                  "\x28\xc0\x26\x30\xd1\x19\x9c\x1f\x02\x17\xf4\x7c\x96\x20"
                  "\xf3\xef\xe8\x27\x15\xae", CURL_SHA256_DIGEST_LENGTH);
  }
#endif

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

#ifdef CURL_HAVE_MD5
  {
    static const char password[] = "Pa55worD";
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    unsigned char output[MD5_DIGEST_LEN];

    Curl_hmacit(&Curl_HMAC_MD5,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string1, strlen(string1),
                output);

    verify_memory(output, "\xd1\x29\x75\x43\x58\xdc\xab\x78\xdf\xcd\x7f\x2b"
                  "\x29\x31\x13\x37", MD5_DIGEST_LEN);

    Curl_hmacit(&Curl_HMAC_MD5,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string2, strlen(string2),
                output);

    verify_memory(output, "\x75\xf1\xa7\xb9\xf5\x40\xe5\xa4\x98\x83\x9f\x64"
                  "\x5a\x27\x6d\xd0", MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    static const char password[] = "Pa55worD";
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    unsigned char output[CURL_SHA256_DIGEST_LENGTH];

    Curl_hmacit(&Curl_HMAC_SHA256,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string1, strlen(string1),
                output);

    verify_memory(output, "\x8c\x9d\x74\x0f\x32\xf7\xbb\xb7\xec\xe0\x07\x7e"
                  "\xc1\x8e\x1f\xdb\x17\x02\x6e\xaf\x9c\xcf\x76\x3d\x26\x88"
                  "\x56\x6d\xc8\x07\xbf\x59", CURL_SHA256_DIGEST_LENGTH);

    Curl_hmacit(&Curl_HMAC_SHA256,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string2, strlen(string2),
                output);

    verify_memory(output, "\xe4\x81\x63\x53\xab\xc6\x8c\x34\xd4\xa8\xe5\xc8"
                  "\xf3\x1d\x12\xbd\xaf\xd6\x58\x73\x11\xe9\xe6\xf9\x93\x2e"
                  "\x0a\xba\x69\x49\x63\x8c", CURL_SHA256_DIGEST_LENGTH);
  }
#endif
#endif /* feature using HMAC */

  UNITTEST_END(curl_global_cleanup())
}
