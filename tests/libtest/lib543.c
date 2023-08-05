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
/* Based on Alex Fishman's bug report on September 30, 2007 */

#include "test.h"

#include "memdebug.h"

int test(char *URL)
{
  static const unsigned char a[] = {
      0x9c, 0x26, 0x4b, 0x3d, 0x49, 0x4, 0xa1, 0x1,
      0xe0, 0xd8, 0x7c,  0x20, 0xb7, 0xef, 0x53, 0x29, 0xfa,
      0x1d, 0x57, 0xe1};

  CURL *easy;
  CURLcode res = CURLE_OK;
  (void)URL;

  global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    fprintf(stderr, "curl_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
  }
  else {
    int asize = (int)sizeof(a);
    char *s = curl_easy_escape(easy, (const char *)a, asize);

    if(s) {
      printf("%s\n", s);
      curl_free(s);
    }

    s = curl_easy_escape(easy, "", 0);
    if(s) {
      printf("IN: '' OUT: '%s'\n", s);
      curl_free(s);
    }
    s = curl_easy_escape(easy, " 123", 3);
    if(s) {
      printf("IN: ' 12' OUT: '%s'\n", s);
      curl_free(s);
    }

    curl_easy_cleanup(easy);
  }
  curl_global_cleanup();

  return (int)res;
}
