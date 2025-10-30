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

static CURLcode test_unit1983(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *input;
    const char *expected;
  };

  static const struct testcase testcases[] = {
    {
      "simple-text",
      "hello",
      "hello"
    },
    {
      "space-encode",
      "hello world",
      "hello%20world"
    },
    {
      "percent-normalize",
      "hello%2bworld",
      "hello%2Bworld"
    },
    {
      "mixed-case-hex",
      "test%2f%3a%2b",
      "test%2F%3A%2B"
    },
    {
      "unreserved-chars",
      "test-._~123ABCabc",
      "test-._~123ABCabc"
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct dynbuf result_output;
    char *output_ptr;
    int result;

    curlx_dyn_init(&result_output, CURL_MAX_HTTP_HEADER);

    result = http_aws_decode_encode(testcases[i].input,
                                    strlen(testcases[i].input),
                                    &result_output);
    output_ptr = curlx_dyn_ptr(&result_output);

    fail_unless(!result && output_ptr &&
                !strcmp(output_ptr, testcases[i].expected),
                testcases[i].testname);
    curlx_dyn_free(&result_output);
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
