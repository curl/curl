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

#include "curl_md4.h"

static CURLcode test_unit1611(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_CURL_NTLM_CORE
  static const char string1[] = "1";
  static const char string2[] = "hello-you-fool";
  unsigned char output[MD4_DIGEST_LENGTH];
  unsigned char *testp = output;

  Curl_md4it(output, (const unsigned char *) string1, strlen(string1));

  verify_memory(testp,
                "\x8b\xe1\xec\x69\x7b\x14\xad\x3a\x53\xb3\x71\x43\x61\x20\x64"
                "\x1d", MD4_DIGEST_LENGTH);

  Curl_md4it(output, (const unsigned char *) string2, strlen(string2));

  verify_memory(testp,
                "\xa7\x16\x1c\xad\x7e\xbe\xdb\xbc\xf8\xc7\x23\x10\x2d\x2c\xe2"
                "\x0b", MD4_DIGEST_LENGTH);
#endif

  UNITTEST_END_SIMPLE
}
