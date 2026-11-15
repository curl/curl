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

static CURLcode test_unit1612(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifndef CURL_DISABLE_DIGEST_AUTH
#ifdef CURL_HAVE_MD5
  {
    static const char password[] = "Pa55worD";
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    unsigned char output[CURL_MD5_DIGEST_LEN];

    Curl_hmacit(&Curl_HMAC_MD5,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string1, strlen(string1),
                output);

    verify_memory(output, "\xd1\x29\x75\x43\x58\xdc\xab\x78\xdf\xcd\x7f\x2b"
                  "\x29\x31\x13\x37", CURL_MD5_DIGEST_LEN);

    Curl_hmacit(&Curl_HMAC_MD5,
                (const unsigned char *)password, strlen(password),
                (const unsigned char *)string2, strlen(string2),
                output);

    verify_memory(output, "\x75\xf1\xa7\xb9\xf5\x40\xe5\xa4\x98\x83\x9f\x64"
                  "\x5a\x27\x6d\xd0", CURL_MD5_DIGEST_LEN);
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
#endif /* CURL_DISABLE_DIGEST_AUTH */

  UNITTEST_END_SIMPLE
}
