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

#include "curl_hmac.h"
#include "curl_md5.h"

static CURLcode test_unit1612(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if (defined(USE_CURL_NTLM_CORE) && !defined(USE_WINDOWS_SSPI)) || \
  !defined(CURL_DISABLE_DIGEST_AUTH)

  static const char password[] = "Pa55worD";
  static const char string1[] = "1";
  static const char string2[] = "hello-you-fool";
  unsigned char output[HMAC_MD5_LENGTH];
  unsigned char *testp = output;

  Curl_hmacit(&Curl_HMAC_MD5,
              (const unsigned char *) password, strlen(password),
              (const unsigned char *) string1, strlen(string1),
              output);

  verify_memory(testp,
                "\xd1\x29\x75\x43\x58\xdc\xab\x78\xdf\xcd\x7f\x2b\x29\x31\x13"
                "\x37", HMAC_MD5_LENGTH);

  Curl_hmacit(&Curl_HMAC_MD5,
              (const unsigned char *) password, strlen(password),
              (const unsigned char *) string2, strlen(string2),
              output);

  verify_memory(testp,
                "\x75\xf1\xa7\xb9\xf5\x40\xe5\xa4\x98\x83\x9f\x64\x5a\x27\x6d"
                "\xd0", HMAC_MD5_LENGTH);
#endif

  UNITTEST_END_SIMPLE
}
