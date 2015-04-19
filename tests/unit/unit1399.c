/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "tool_operhlp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memdebug.h" /* LAST include file */

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START

  const char *values[] = {
    "http://example.com",                                     "",
    "http://example.com/",                                    "",
    "http://example.com/hello.jpg",                           "hello.jpg",
    "ftp://example.com/hello.jpg",                            "hello.jpg",
    "http://example.com/hello.jpg?stuff=things",              "hello.jpg",
    "http://example.com/hello.jpg#section1",                  "hello.jpg",
    "http://example.com/hello.jpg?stuff=things#section1",     "hello.jpg",
    "http://example.com/hello%3Fthere.jpg",                   "hello?there.jpg",
    "http://example.com/hello%00there.jpg",                   NULL,
    "http://example.com/hello%1Fthere.jpg",                   NULL,
    "http://example.com/hello%23there.jpg",                   "hello#there.jpg",
    "http://example.com/asdf/hello.jpg",                      "hello.jpg",
    "http://example.com/hello%20there.jpg",                   "hello there.jpg",
    "http://example.com/hello%20there.jpg?a=b",               "hello there.jpg",
    "http://example.com/hello%20there.jpg#s1",                "hello there.jpg",
    "http://example.com/..%2F..%2Fetc%2Fhello.jpg",           "hello.jpg",
    "http://example.com/..%5CWindows%5CSystem32%5Chello.jpg", "hello.jpg",
    "http://example.com/..%5Cdir1%2Fhello.jpg",               "hello.jpg",
    "http://example.com/..%2Fdir1%5Chello.jpg",               "hello.jpg",
    NULL,                                                     NULL,
  };

  const char **p;
  const char *url, *expected_fn;
  char *actual_fn;
  CURLcode res;

  for(p = values; *p; p += 2) {
    url = p[0];
    expected_fn = p[1];

    res = get_url_file_name(&actual_fn, url);
    if(res != CURLE_OK) {
      if(expected_fn != NULL) {
        printf("get_url_file_name != CURLE_OK for url '%s': %s\n", url,
            curl_easy_strerror(res));
        fail("get_url_file_name not CURLE_OK");
      }
      continue;
    }

    if(strcmp(expected_fn, actual_fn) != 0) {
      printf("expected filename '%s' from url '%s' but got '%s'\n",
          expected_fn, url, actual_fn);
      fail("assertion failed");
    }

    Curl_safefree(actual_fn);
  }

UNITTEST_STOP
