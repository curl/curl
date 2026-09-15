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

#ifdef CURL_HAVE_DIAG
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#endif

static CURLcode test_lib1451(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef _WIN32
  /* bare "%I" must track native pointer/size_t width, not curl_off_t */
  {
    struct {
      unsigned char guard1[8];
      size_t count;
      unsigned char guard2[8];
    } canary;
    unsigned char expect_guard[8];
    char buf[64];
    int rc;

    memset(&canary, 0xaa, sizeof(canary));
    memset(expect_guard, 0xaa, sizeof(expect_guard));

    rc = curl_msnprintf(buf, sizeof(buf), "0123456789%In", &canary.count);
    fail_unless(rc == 10, "curl_msnprintf returned unexpected length");
    fail_unless(canary.count == 10, "%In wrote the wrong count");
    verify_memory(canary.guard1, expect_guard, sizeof(expect_guard));
    verify_memory(canary.guard2, expect_guard, sizeof(expect_guard));
  }

  {
    char buf[64];
    curl_msnprintf(buf, sizeof(buf), "%Iu-%d", (size_t)0x11223344, 42);
    fail_unless(!strcmp(buf, "287454020-42"),
                "%Iu did not consume a size_t-sized argument");
  }
#endif

  UNITTEST_END_SIMPLE
}

#ifdef CURL_HAVE_DIAG
#pragma GCC diagnostic pop
#endif
