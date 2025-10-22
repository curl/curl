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
#include "../libtest/unitcheck.h"

#include "http_aws_sigv4.h"
#include "urldata.h"
#include "curl_memory.h"

static CURLcode test_unit1981(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct Curl_easy data;
  struct connectdata conn;
  CURLcode result;

  memset(&data, 0, sizeof(data));
  memset(&conn, 0, sizeof(conn));
  data.conn = &conn;
  conn.host.name = Curl_cstrdup("examplebucket.s3.amazonaws.com");

  /* Test token in header mode */
  data.set.str[STRING_AWS_SIGV4] = Curl_cstrdup("aws:amz:us-east-1:s3");
  data.state.aptr.user = Curl_cstrdup("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/"
                                      "K7MDENG/bPxRfiCYEXAMPLEKEY:"
                                      "AQoDYXdzEJr");
  data.state.url = Curl_cstrdup("https://examplebucket.s3.amazonaws.com/"
                                "test.txt");

  result = Curl_output_aws_sigv4(&data);
  if(result == CURLE_OK) {
    char *auth_headers = data.state.aptr.userpwd;
    if(!auth_headers || !strstr(auth_headers, "X-Amz-Security-Token")) {
      fail_unless(0, "Security token not found in headers");
    }
  }

  /* Test token in querystring mode */
  data.set.str[STRING_AWS_SIGV4_MODE] = Curl_cstrdup("querystring");
  result = Curl_output_aws_sigv4(&data);
  if(result == CURLE_OK) {
    if(!data.state.up.query ||
       !strstr(data.state.up.query, "X-Amz-Security-Token")) {
      fail_unless(0, "Security token not found in query string");
    }
  }

  /* Test invalid mode */
  data.set.str[STRING_AWS_SIGV4_MODE] = Curl_cstrdup("invalidmode");
  data.state.aptr.user = Curl_cstrdup("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/"
                                      "K7MDENG/bPxRfiCYEXAMPLEKEY");
  result = Curl_output_aws_sigv4(&data);
  if(result == CURLE_OK) {
    char *auth_headers = data.state.aptr.userpwd;
    if(!auth_headers) {
      fail_unless(auth_headers, "Authorization header not found");
    }
  }

  /* Cleanup */
  if(conn.host.name)
    free(conn.host.name);
  if(data.set.str[STRING_AWS_SIGV4])
    free(data.set.str[STRING_AWS_SIGV4]);
  if(data.state.aptr.user)
    free(data.state.aptr.user);
  if(data.state.url)
    free(data.state.url);
  if(data.set.str[STRING_AWS_SIGV4_MODE])
    free(data.set.str[STRING_AWS_SIGV4_MODE]);

#endif

  UNITTEST_END_SIMPLE
}
