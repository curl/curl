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
#include "tool_dirhie.h"
#include "tool_stderr.h"

static CURLcode test_tool1720(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const char *check[] = {
    "",
    "(null)",
    "filename",
    "(null)",
    "foo/bar/",
    "foo|foo/bar|",
    "foo/bar/filename",
    "foo|foo/bar|",
    "/foo/bar/filename",
    "/foo|/foo/bar|",
#if defined(_WIN32) || defined(MSDOS)
    "C:/foo/bar/filename",
    "C:/foo|C:/foo/bar|",
    "C:foo/bar/filename",
    "C:foo|C:foo/bar|",
    "foo\\bar\\filename",
    "foo|foo\\bar|",
    "\\foo\\bar\\filename",
    "\\foo|\\foo\\bar|",
    "C:\\foo\\bar\\filename",
    "C:\\foo|C:\\foo\\bar|",
    "C:foo\\bar\\filename",
    "C:foo|C:foo\\bar|",
#endif
  };

  size_t i;
  struct dynbuf *res = create_dir_hierarchy_trace_dynres();

  tool_init_stderr();

  curlx_dyn_init(res, 256);

  for(i = 0; i < CURL_ARRAYSIZE(check); i += 2) {
    const char *actual;
    curlx_dyn_reset(res);
    create_dir_hierarchy(check[i]);
    actual = curlx_dyn_ptr(res);
    if(!actual)
      actual = "(null)";
    if(strcmp(check[i + 1], actual)) {
      curl_mprintf("Expected '%s' got '%s'\n", check[i + 1], actual);
      unitfail++;
    }
  }

  curlx_dyn_free(res);

  UNITTEST_END_SIMPLE
}
