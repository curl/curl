/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "curl_sha256.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START

#ifndef CURL_DISABLE_CRYPTO_AUTH
  const char string1[] = "1";
  const char string2[] = "hello-you-fool";
  unsigned char output[SHA256_DIGEST_LENGTH];
  unsigned char *testp = output;

  Curl_sha256it(output, (const unsigned char *) string1, strlen(string1));

  verify_memory(testp,
                "\x6b\x86\xb2\x73\xff\x34\xfc\xe1\x9d\x6b\x80\x4e\xff\x5a\x3f"
                "\x57\x47\xad\xa4\xea\xa2\x2f\x1d\x49\xc0\x1e\x52\xdd\xb7\x87"
                "\x5b\x4b", SHA256_DIGEST_LENGTH);

  Curl_sha256it(output, (const unsigned char *) string2, strlen(string2));

  verify_memory(testp,
                "\xcb\xb1\x6a\x8a\xb9\xcb\xb9\x35\xa8\xcb\xa0\x2e\x28\xc0\x26"
                "\x30\xd1\x19\x9c\x1f\x02\x17\xf4\x7c\x96\x20\xf3\xef\xe8\x27"
                "\x15\xae", SHA256_DIGEST_LENGTH);
#endif


UNITTEST_STOP
