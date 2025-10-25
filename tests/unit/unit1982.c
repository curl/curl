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

#include "http_aws_sigv4.h"

static CURLcode test_unit1982(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *path;
    bool do_uri_encode;
    const char *expected;
  };

  static const struct testcase testcases[] = {
    {
      "empty-path",
      "",
      true,
      "/"
    },
    {
      "root-path",
      "/",
      true,
      "/"
    },
    {
      "simple-path",
      "/test",
      true,
      "/test"
    },
    {
      "path-with-spaces",
      "/test path",
      true,
      "/test%20path"
    },
    {
      "path-no-encode",
      "/test path",
      false,
      "/test path"
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct dynbuf canonical_path;
    char *canonical_path_ptr;
    int result;

    curlx_dyn_init(&canonical_path, CURL_MAX_HTTP_HEADER);

    result = canon_path(testcases[i].path, strlen(testcases[i].path),
                        &canonical_path, testcases[i].do_uri_encode);
    canonical_path_ptr = curlx_dyn_ptr(&canonical_path);

    fail_unless(!result && canonical_path_ptr &&
                !strcmp(canonical_path_ptr, testcases[i].expected),
                testcases[i].testname);
    curlx_dyn_free(&canonical_path);
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
