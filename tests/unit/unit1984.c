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
#include "http_aws_sigv4.h"

static CURLcode test_unit1984(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const char *user;
    const char *passwd;
    const char *expected_access_key;
    const char *expected_secret_key;
    const char *expected_security_token;
    CURLcode expected_result;
  };

  static const struct testcase testcases[] = {
    {
      "no-token",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      NULL,
      CURLE_OK
    },
    {
      "with-token",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:AQoDYXdzEJr",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "AQoDYXdzEJr",
      CURLE_OK
    },
    {
      "token-with-special-chars",
      "AKIAIOSFODNN7EXAMPLE",
      "secret:IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDTGfn+S=",
      "AKIAIOSFODNN7EXAMPLE",
      "secret",
      "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDTGfn+S=",
      CURLE_OK
    },
    {
      "empty-token",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "",
      CURLE_OK
    },
    {
      "no-user",
      NULL,
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      NULL,
      NULL,
      NULL,
      CURLE_BAD_FUNCTION_ARGUMENT
    },
    {
      "no-passwd",
      "AKIAIOSFODNN7EXAMPLE",
      NULL,
      NULL,
      NULL,
      NULL,
      CURLE_BAD_FUNCTION_ARGUMENT
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct Curl_easy data;
    const char *access_key = NULL;
    char *secret_key = NULL;
    char *security_token = NULL;
    char *user_copy = NULL, *passwd_copy = NULL;
    CURLcode result;

    /* Initialize minimal data structure */
    memset(&data, 0, sizeof(data));

    if(testcases[i].user) {
      user_copy = Curl_cstrdup(testcases[i].user);
    }
    if(testcases[i].passwd) {
      passwd_copy = Curl_cstrdup(testcases[i].passwd);
    }
    data.state.aptr.user = user_copy;
    data.state.aptr.passwd = passwd_copy;

    result = parse_aws_credentials(&data, &access_key, &secret_key,
                                   &security_token);

    fail_unless(result == testcases[i].expected_result, testcases[i].testname);

    if(result == CURLE_OK) {
      if(testcases[i].expected_access_key) {
        fail_unless(access_key &&
                    !strcmp(access_key, testcases[i].expected_access_key),
                    testcases[i].testname);
      }
      if(testcases[i].expected_secret_key) {
        fail_unless(secret_key &&
                    !strcmp(secret_key, testcases[i].expected_secret_key),
                    testcases[i].testname);
      }
      if(testcases[i].expected_security_token) {
        fail_unless(security_token && !strcmp(security_token,
                    testcases[i].expected_security_token),
                    testcases[i].testname);
      }
      else {
        fail_unless(security_token == NULL, testcases[i].testname);
      }
    }

    /* Clean up allocated memory from parse_aws_credentials */
    curl_free(secret_key);
    curl_free(security_token);

    /* Clean up our allocated copies (let them leak to avoid corruption) */
    /* curl_free(user_copy); curl_free(passwd_copy); */
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
