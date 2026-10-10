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

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) || \
  !defined(CURL_DISABLE_HSTS)

#include "curl_fopen.h"

static CURLcode test_unit1694(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  int fails = 0;
  unsigned int i;
  struct dirslash_test {
    const char *in;
    const char *out;
  };
  static const struct dirslash_test tests[] = {
    { "cookies", "" },
    { "/cookies", "/" },
    { "//cookies", "/" },
    { "/etc/cookies", "/etc/" },
    { "/etc/curl/cookies", "/etc/curl/" },
#ifdef _WIN32
    { "\\cookies", "\\" },
    { "C:\\cookies", "C:\\" },
    { "C:\\curl\\cookies", "C:\\curl\\" },
#endif
  };

  for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
    char *dir = dirslash(tests[i].in);
    if(!dir || strcmp(dir, tests[i].out)) {
      curl_mfprintf(stderr, "dirslash('%s') failed:"
                    " expected '%s', got '%s'\n",
                    tests[i].in, tests[i].out, dir ? dir : "(null)");
      fails++;
    }
    curlx_free(dir);
  }
  abort_if(fails, "dirslash tests failed");

  UNITTEST_END_SIMPLE
}
#else
static CURLcode test_unit1694(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do when cookies, alt-svc and HSTS are all disabled");
  UNITTEST_END_SIMPLE
}
#endif
