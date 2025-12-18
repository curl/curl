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

static CURLcode test_unit1980(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *query_part;
    const char *canonical_query;
  };

  static const struct testcase testcases[] = {
    {
      "no-value",
      "Param1=",
      "Param1="
    },
    {
      "test-439",
      "name=me&noval&aim=b%aad&weirdo=*.//-",
      "aim=b%AAd&name=me&noval=&weirdo=%2A.%2F%2F-"
    },
    {
      "blank-query-params",
      "hello=a&b&c=&d",
      "b=&c=&d=&hello=a"
    },
    {
      "get-vanilla-query-order-key-case",
      "Param2=value2&Param1=value1",
      "Param1=value1&Param2=value2"
    },
    {
      "get-vanilla-query-unreserved",
      "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
      "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
      "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    },
    {
      "get-vanilla-empty-query-key",
      "Param1=value1",
      "Param1=value1"
    },
    {
      "get-vanilla-query-order-encoded",
      "Param-3=Value3&Param=Value2&%E1%88%B4=Value1",
      "%E1%88%B4=Value1&Param=Value2&Param-3=Value3"
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct dynbuf canonical_query;

    char buffer[1024];
    char *canonical_query_ptr;
    int result;
    int msnprintf_result;

    curlx_dyn_init(&canonical_query, CURL_MAX_HTTP_HEADER);

    result = canon_query(testcases[i].query_part, &canonical_query);
    canonical_query_ptr = curlx_dyn_ptr(&canonical_query);
    msnprintf_result = curl_msnprintf(buffer, sizeof(buffer),
                                      "%s: Received \"%s\" "
                                      "and should be \"%s\"",
                                      testcases[i].testname,
                                      canonical_query_ptr,
                                      testcases[i].canonical_query);
    fail_unless(msnprintf_result >= 0, "curl_msnprintf fails");
    fail_unless(!result && canonical_query_ptr &&
                !strcmp(canonical_query_ptr, testcases[i].canonical_query),
                buffer);
    curlx_dyn_free(&canonical_query);
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
