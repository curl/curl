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

static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(_WIN32) && defined(UNICODE)
  static const wchar_t name_w[] = L"CURL_UNITTEST_GETENV";
  static const wchar_t value_w[] = L"curl-\x6f22\x5b57";
  static const char value_utf8[] =
    "curl-\xe6\xbc\xa2\xe5\xad\x97";
  char *value;

  fail_unless(SetEnvironmentVariableW(name_w, value_w),
              "failed to set Unicode environment value");

  value = curl_getenv("CURL_UNITTEST_GETENV");
  fail_unless(value, "curl_getenv returned NULL");
  if(value) {
    fail_unless(!strcmp(value, value_utf8),
                "curl_getenv did not return UTF-8");
    curl_free(value);
  }

  fail_unless(SetEnvironmentVariableW(name_w, NULL),
              "failed to remove environment value");
#endif

  UNITTEST_END_SIMPLE
}
