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
#include "tool_findfile.h"

static CURLcode test_tool3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(_WIN32) && defined(UNICODE)
  static const wchar_t dirname_w[] = L"curl-home-\x6f22\x5b57";
  static const wchar_t filename_w[] =
    L"curl-home-\x6f22\x5b57\\_curlrc";
  static const char expected[] =
    "curl-home-\xe6\xbc\xa2\xe5\xad\x97\\_curlrc";
  FILE *file;
  char *path;

  (void)DeleteFileW(filename_w);
  (void)RemoveDirectoryW(dirname_w);

  fail_unless(CreateDirectoryW(dirname_w, NULL),
              "failed to create Unicode directory");

  file = curlx_fopen(expected, "wb");
  fail_unless(file,
              "failed to create Unicode config file");
  if(file)
    curlx_fclose(file);

  fail_unless(SetEnvironmentVariableW(L"CURL_HOME", dirname_w),
              "failed to set Unicode CURL_HOME");

  path = findfile(".curlrc", CURLRC_DOTSCORE, TRUE);
  fail_unless(path, "findfile did not find the Unicode config path");
  if(path) {
    fail_unless(!strcmp(path, expected),
                "findfile did not return the UTF-8 config path");
    curlx_free(path);
  }

  (void)SetEnvironmentVariableW(L"CURL_HOME", NULL);
  (void)DeleteFileW(filename_w);
  (void)RemoveDirectoryW(dirname_w);
#else
  curl_mfprintf(stderr, "Skipped test not for Windows Unicode builds\n");
#endif

  UNITTEST_END_SIMPLE
}
