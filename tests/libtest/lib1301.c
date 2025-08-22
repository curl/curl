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
#include "first.h"

#define t1301_fail_unless(expr, msg)                             \
  do {                                                           \
    if(!(expr)) {                                                \
      curl_mfprintf(stderr, "%s:%d Assertion '%s' FAILED: %s\n", \
                    __FILE__, __LINE__, #expr, msg);             \
      return TEST_ERR_FAILURE;                                   \
    }                                                            \
  } while(0)

static CURLcode test_lib1301(const char *URL)
{
  int rc;
  (void)URL;

  rc = curl_strequal("iii", "III");
  t1301_fail_unless(rc != 0, "return code should be non-zero");

  rc = curl_strequal("iiia", "III");
  t1301_fail_unless(rc == 0, "return code should be zero");

  rc = curl_strequal("iii", "IIIa");
  t1301_fail_unless(rc == 0, "return code should be zero");

  rc = curl_strequal("iiiA", "IIIa");
  t1301_fail_unless(rc != 0, "return code should be non-zero");

  rc = curl_strnequal("iii", "III", 3);
  t1301_fail_unless(rc != 0, "return code should be non-zero");

  rc = curl_strnequal("iiiABC", "IIIcba", 3);
  t1301_fail_unless(rc != 0, "return code should be non-zero");

  rc = curl_strnequal("ii", "II", 3);
  t1301_fail_unless(rc != 0, "return code should be non-zero");

  return CURLE_OK;
}
