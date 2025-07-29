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

#include "urldata.h"
#include "curl_ntlm_core.h"

static CURLcode t1600_setup(CURL **easy)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return res;
}

static void t1600_stop(CURL *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static CURLcode test_unit1600(char *arg)
{
  CURL *easy;

  UNITTEST_BEGIN(t1600_setup(&easy))

#if defined(USE_NTLM) && (!defined(USE_WINDOWS_SSPI) || \
                          defined(USE_WIN32_CRYPTO))
  unsigned char output[21];
  unsigned char *testp = output;
  Curl_ntlm_core_mk_nt_hash("1", output);

  verify_memory(testp,
              "\x69\x94\x3c\x5e\x63\xb4\xd2\xc1\x04\xdb"
              "\xbc\xc1\x51\x38\xb7\x2b\x00\x00\x00\x00\x00", 21);

  Curl_ntlm_core_mk_nt_hash("hello-you-fool", output);

  verify_memory(testp,
              "\x39\xaf\x87\xa6\x75\x0a\x7a\x00\xba\xa0"
              "\xd3\x4f\x04\x9e\xc1\xd0\x00\x00\x00\x00\x00", 21);

  /* !checksrc! disable LONGLINE 2 */
  Curl_ntlm_core_mk_nt_hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", output);

  verify_memory(testp,
                "\x36\x9d\xae\x06\x84\x7e\xe1\xc1\x4a\x94\x39\xea\x6f\x44\x8c\x65\x00\x00\x00\x00\x00", 21);
#endif

  UNITTEST_END(t1600_stop(easy))
}
