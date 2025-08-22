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

static CURLcode test_unit1979(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)
  struct testcase {
    const char *testname;
    const bool normalize;
    const char *url_part;
    const char *canonical_url;
  };

  static const struct testcase testcases[] = {
    {
      "test-equals-encode",
      true,
      "/a=b",
      "/a%3Db"
    },
    {
      "test-equals-noencode",
      false,
      "/a=b",
      "/a=b"
    },
    {
      "test-s3-tables",
      true,
      "/tables/arn%3Aaws%3As3tables%3Aus-east-1%3A022954301426%3Abucket%2Fja"
      "soehartablebucket/jasoeharnamespace/jasoehartable/encryption",
      "/tables/arn%253Aaws%253As3tables%253Aus-east-1%253A022954301426%253Ab"
      "ucket%252Fjasoehartablebucket/jasoeharnamespace/jasoehartable/encrypt"
      "ion"
    },
    {
      "get-vanilla",
      true,
      "/",
      "/"
    },
    {
      "get-unreserved",
      true,
      "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    },
    {
      "get-slashes-unnormalized",
      false,
      "//example//",
      "//example//"
    },
    {
      "get-space-normalized",
      true,
      "/example space/",
      "/example%20space/"
    },
    {
      "get-slash-dot-slash-unnormalized",
      false,
      "/./",
      "/./"
    },
    {
      "get-slash-unnormalized",
      false,
      "//",
      "//"
    },
    {
      "get-relative-relative-unnormalized",
      false,
      "/example1/example2/../..",
      "/example1/example2/../.."
    }
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(testcases); i++) {
    struct dynbuf canonical_path;

    char buffer[1024];
    char *canonical_path_string;
    int result;
    int msnprintf_result;

    curlx_dyn_init(&canonical_path, CURL_MAX_HTTP_HEADER);

    result = canon_path(testcases[i].url_part, strlen(testcases[i].url_part),
                        &canonical_path, testcases[i].normalize);
    canonical_path_string = curlx_dyn_ptr(&canonical_path);
    msnprintf_result = curl_msnprintf(buffer, sizeof(buffer),
                                      "%s: Received \"%s\" "
                                      "and should be \"%s\", normalize (%d)",
                                      testcases[i].testname,
                                      curlx_dyn_ptr(&canonical_path),
                                      testcases[i].canonical_url,
                                      testcases[i].normalize);
    fail_unless(msnprintf_result >= 0, "curl_msnprintf fails");
    fail_unless(!result && canonical_path_string &&
                !strcmp(canonical_path_string, testcases[i].canonical_url),
                buffer);
    curlx_dyn_free(&canonical_path);
  }
#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */

  UNITTEST_END_SIMPLE
}
