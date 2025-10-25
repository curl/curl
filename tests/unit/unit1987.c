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
#include "transfer.h"

static CURLcode test_unit1987(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *credential_raw;
    const char *security_token_raw;
    const char *expected_credential_canonical;
    const char *expected_credential_wire;
    const char *expected_token_canonical;
    const char *expected_token_wire;
  };

  static const struct testcase testcases[] = {
    {
      "basic-credential",
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      NULL,
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      "AKIAIOSFODNN7EXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request",
      NULL,
      NULL
    },
    {
      "credential-with-special-chars",
      "AKIA+TEST/2015-08-30/us-east-1/s3/aws4_request",
      NULL,
      "AKIA+TEST/2015-08-30/us-east-1/s3/aws4_request",
      "AKIA%2BTEST%2F2015-08-30%2Fus-east-1%2Fs3%2Faws4_request",
      NULL,
      NULL
    },
    {
      "security-token-basic",
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      "AQoDYXdzEJr",
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      "AKIAIOSFODNN7EXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request",
      "AQoDYXdzEJr",
      "AQoDYXdzEJr"
    },
    {
      "security-token-with-special-chars",
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDTGfn+S=",
      "AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request",
      "AKIAIOSFODNN7EXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request",
      "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDTGfn+S=",
      "IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJI"
      "MEUCIQDTGfn%2BS%3D"
    },
    {
      "sigv4a-credential-basic",
      "AKIAIOSFODNN7EXAMPLE/20150830/s3/aws4_request",
      NULL,
      "AKIAIOSFODNN7EXAMPLE/20150830/s3/aws4_request",
      "AKIAIOSFODNN7EXAMPLE%2F20150830%2Fs3%2Faws4_request",
      NULL,
      NULL
    },
    {
      "sigv4a-credential-with-token",
      "AKIAIOSFODNN7EXAMPLE/20150830/s3/aws4_request",
      "AQoDYXdzEJr",
      "AKIAIOSFODNN7EXAMPLE/20150830/s3/aws4_request",
      "AKIAIOSFODNN7EXAMPLE%2F20150830%2Fs3%2Faws4_request",
      "AQoDYXdzEJr",
      "AQoDYXdzEJr"
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct dynbuf canonical_query;
    struct dynbuf wire_query;
    char *canonical_ptr, *wire_ptr;
    CURLcode result;

    curlx_dyn_init(&canonical_query, CURL_MAX_HTTP_HEADER);
    curlx_dyn_init(&wire_query, CURL_MAX_HTTP_HEADER);

    /* Build canonical query (for signature calculation) */
    result = curlx_dyn_addf(&canonical_query, "X-Amz-Credential=%s",
                            testcases[i].expected_credential_canonical);
    fail_unless(!result, "Failed to build canonical query");

    if(testcases[i].security_token_raw) {
      result = curlx_dyn_addf(&canonical_query, "&X-Amz-Security-Token=%s",
                              testcases[i].expected_token_canonical);
      fail_unless(!result, "Failed to add token to canonical query");
    }

    /* Add X-Amz-Region-Set test for multi-region case */
    if(i == 0) { /* Only test on first case */
      result = curlx_dyn_addf(&canonical_query, "&X-Amz-Region-Set=%s",
                              "us-east-1,us-west-2");
      fail_unless(!result, "Failed to add region set to canonical query");
    }

    /* Build wire query (for actual HTTP request) */
    result = curlx_dyn_addf(&wire_query, "X-Amz-Credential=%s",
                            testcases[i].expected_credential_wire);
    fail_unless(!result, "Failed to build wire query");

    if(testcases[i].security_token_raw) {
      result = curlx_dyn_addf(&wire_query, "&X-Amz-Security-Token=%s",
                              testcases[i].expected_token_wire);
      fail_unless(!result, "Failed to add token to wire query");
    }

    /* Add X-Amz-Region-Set test for multi-region case */
    if(i == 0) { /* Only test on first case */
      result = curlx_dyn_addf(&wire_query, "&X-Amz-Region-Set=%s",
                              "us-east-1%2Cus-west-2");
      fail_unless(!result, "Failed to add region set to wire query");
    }

    canonical_ptr = curlx_dyn_ptr(&canonical_query);
    wire_ptr = curlx_dyn_ptr(&wire_query);

    /* Verify credential encoding in canonical query */
    fail_unless(strstr(canonical_ptr,
                       testcases[i].expected_credential_canonical),
                testcases[i].testname);

    /* Verify credential encoding in wire query */
    fail_unless(strstr(wire_ptr, testcases[i].expected_credential_wire),
                testcases[i].testname);

    /* Test SigV4 vs SigV4A credential format differences */
    if(i < 4) {
      /* SigV4 cases should include region */
      fail_unless(strstr(testcases[i].expected_credential_canonical,
                         "/us-east-1/"),
                  "SigV4 credential should include region");
    }
    else {
      /* SigV4A cases should exclude region */
      fail_unless(!strstr(testcases[i].expected_credential_canonical,
                          "/us-east-1/"),
                  "SigV4A credential should exclude region");
      fail_unless(strstr(testcases[i].expected_credential_canonical,
                         "/s3/aws4_request"),
                  "SigV4A credential should have service/aws4_request");
    }

    /* Verify security token encoding if present */
    if(testcases[i].security_token_raw) {
      fail_unless(strstr(canonical_ptr, testcases[i].expected_token_canonical),
                  testcases[i].testname);
      fail_unless(strstr(wire_ptr, testcases[i].expected_token_wire),
                  testcases[i].testname);
    }

    /* Verify X-Amz-Region-Set encoding for first test case */
    if(i == 0) {
      fail_unless(strstr(canonical_ptr,
                         "X-Amz-Region-Set=us-east-1,us-west-2"),
                  "Canonical should have unencoded region set");
      fail_unless(strstr(wire_ptr, "X-Amz-Region-Set=us-east-1%2Cus-west-2"),
                  "Wire should have encoded region set");
    }

    /* Verify canonical vs wire differences for special characters */
    if(strchr(testcases[i].credential_raw, '/')) {
      /* Canonical should have raw '/', wire should have '%2F' */
      fail_unless(strstr(canonical_ptr, "/") != NULL,
                  "Canonical query should contain raw '/'");
      fail_unless(strstr(wire_ptr, "%2F") != NULL,
                  "Wire query should contain encoded '%2F'");
    }

    if(testcases[i].security_token_raw &&
       strchr(testcases[i].security_token_raw, '/')) {
      /* Token with '/' should be encoded in wire query */
      fail_unless(strstr(wire_ptr, "%2F") != NULL,
                  "Wire query should encode '/' in security token");
    }

    curlx_dyn_free(&canonical_query);
    curlx_dyn_free(&wire_query);
  }

  /* Test actual credential formatting in SigV4 vs SigV4A */
  {
    struct Curl_easy data;
    struct connectdata conn;
    CURLcode result;

    memset(&data, 0, sizeof(data));
    memset(&conn, 0, sizeof(conn));
    data.conn = &conn;

    /* Set up test data */
    data.state.aptr.user = curl_maprintf("AKIAIOSFODNN7EXAMPLE:"
                                          "wJalrXUtnFEMI/K7MDENG/"
                                          "bPxRfiCYEXAMPLEKEY");
    data.state.url = curl_maprintf("https://s3.amazonaws.com/"
                                    "examplebucket/test.txt");

    /* Test SigV4 */
    data.set.str[STRING_AWS_SIGV4] = curl_maprintf("aws:amz:us-east-1:s3");
    result = Curl_output_aws_sigv4(&data);
    if(result == CURLE_OK) {
      /* Check Authorization header contains region in credential */
      char *auth_header = Curl_checkheaders(&data, STRCONST("Authorization"));
      if(auth_header) {
        fail_unless(strstr(auth_header, "/us-east-1/"),
                    "SigV4 should include region in credential");
      }
    }

    /* Test SigV4A */
    curl_free(data.set.str[STRING_AWS_SIGV4]);
    data.set.str[STRING_AWS_SIGV4] = curl_maprintf("aws:amz:us-east-1:s3");
    data.set.str[STRING_AWS_SIGV4_ALGORITHM] =
      curl_maprintf("AWS4-ECDSA-P256-SHA256");
    result = Curl_output_aws_sigv4(&data);
    if(result == CURLE_OK) {
      /* Check Authorization header excludes region from credential */
      char *auth_header = Curl_checkheaders(&data, STRCONST("Authorization"));
      if(auth_header) {
        fail_unless(!strstr(auth_header, "/us-east-1/"),
                    "SigV4A should exclude region from credential");
        fail_unless(strstr(auth_header, "/s3/aws4_request"),
                    "SigV4A should have service/aws4_request");
      }
    }

    curl_free(data.state.aptr.user);
    curl_free(data.state.url);
    curl_free(data.set.str[STRING_AWS_SIGV4]);
    curl_free(data.set.str[STRING_AWS_SIGV4_ALGORITHM]);
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
