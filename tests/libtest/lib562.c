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
#include "first.h"

#include "memdebug.h"

/*
 * From "KNOWN_BUGS" April 2009:

 59. If the CURLOPT_PORT option is used on an FTP URL like
 "ftp://example.com/file;type=A" the ";type=A" is stripped off.

 */

static CURLcode test_lib562(const char *URL)
{
  CURLcode res = TEST_ERR_MAJOR_BAD;
  CURL *curl;
  curl_off_t port;

  if(curlx_str_number(&libtest_arg2, &port, 0xffff))
    return res;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return res;
  }

  /* get a curl handle */
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return res;
  }

  /* enable verbose */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* set port number */
  test_setopt(curl, CURLOPT_PORT, (long)port);

  /* specify target */
  test_setopt(curl, CURLOPT_URL, URL);

  /* Now run off and do what you've been told! */
  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
