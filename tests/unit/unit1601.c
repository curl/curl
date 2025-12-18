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

static CURLcode test_unit1601(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if (defined(USE_CURL_NTLM_CORE) && !defined(USE_WINDOWS_SSPI)) || \
  !defined(CURL_DISABLE_DIGEST_AUTH)

  static const char string1[] = "1";
  static const char string2[] = "hello-you-fool";
  unsigned char output[MD5_DIGEST_LEN];
  unsigned char *testp = output;

  Curl_md5it(output, (const unsigned char *) string1, strlen(string1));

  verify_memory(testp, "\xc4\xca\x42\x38\xa0\xb9\x23\x82\x0d\xcc\x50\x9a\x6f"
                "\x75\x84\x9b", MD5_DIGEST_LEN);

  Curl_md5it(output, (const unsigned char *) string2, strlen(string2));

  verify_memory(testp, "\x88\x67\x0b\x6d\x5d\x74\x2f\xad\xa5\xcd\xf9\xb6\x82"
                "\x87\x5f\x22", MD5_DIGEST_LEN);
#endif

  UNITTEST_END_SIMPLE
}
