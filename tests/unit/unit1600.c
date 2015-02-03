/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#include "urldata.h"
#include "curl_ntlm_core.h"

CURL *easy;

static CURLcode unit_setup(void)
{
  easy = curl_easy_init();
  return CURLE_OK;
}

static void unit_stop(void)
{
  curl_easy_cleanup(easy);
}

UNITTEST_START

  unsigned char output[21];
  unsigned char *testp = output;
  Curl_ntlm_core_mk_nt_hash(easy, "1", output);

  verify_memory(testp,
              "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 21);

UNITTEST_STOP
