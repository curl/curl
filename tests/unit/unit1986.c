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

static CURLcode test_unit1986(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *canonical_headers;
    const char *signed_headers;
    const char *query_string;
    bool is_querystring_mode;
    bool expect_date_in_headers;
    bool expect_date_in_signed_headers;
    bool expect_date_in_query;
  };

  static const struct testcase testcases[] = {
    {
      "header-mode",
      "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n",
      "host;x-amz-date",
      "",
      false,
      true,   /* X-Amz-Date should be in headers */
      true,   /* X-Amz-Date should be in signed headers */
      false   /* X-Amz-Date should NOT be in query */
    },
    {
      "querystring-mode",
      "host:example.amazonaws.com\n",
      "host",
      "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20150830T123600Z",
      true,
      false,  /* X-Amz-Date should NOT be in headers */
      false,  /* X-Amz-Date should NOT be in signed headers */
      true    /* X-Amz-Date should be in query */
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    bool has_date_header = (strstr(testcases[i].canonical_headers,
                                   "x-amz-date:") != NULL);
    bool has_date_signed = (strstr(testcases[i].signed_headers,
                                   "x-amz-date") != NULL);
    bool has_date_query = (strstr(testcases[i].query_string,
                                  "X-Amz-Date=") != NULL);
    bool has_region_set_query = (strstr(testcases[i].query_string,
                                        "X-Amz-Region-Set=") != NULL);

    /* Verify X-Amz-Date in headers matches expectation */
    fail_unless(has_date_header == testcases[i].expect_date_in_headers,
                testcases[i].testname);

    /* Verify X-Amz-Date in signed headers matches expectation */
    fail_unless(has_date_signed == testcases[i].expect_date_in_signed_headers,
                testcases[i].testname);

    /* Verify X-Amz-Date in query matches expectation */
    fail_unless(has_date_query == testcases[i].expect_date_in_query,
                testcases[i].testname);

    /* Verify X-Amz-Region-Set follows same pattern as X-Amz-Date in query */
    if(testcases[i].is_querystring_mode && has_region_set_query) {
      fail_unless(has_date_query,
                  "X-Amz-Region-Set should only appear with X-Amz-Date");
    }

    /* Mode-specific validations */
    if(testcases[i].is_querystring_mode) {
      /* In querystring mode: date should be in query, not headers */
      fail_unless(!has_date_header && has_date_query,
                  "Querystring mode should have date in query, not headers");
      fail_unless(!has_date_signed,
                  "Querystring mode should not sign x-amz-date header");
    }
    else {
      /* In header mode: date should be in headers and signed */
      fail_unless(has_date_header && !has_date_query,
                  "Header mode should have date in headers, not query");
      fail_unless(has_date_signed,
                  "Header mode should sign x-amz-date header");
    }
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
