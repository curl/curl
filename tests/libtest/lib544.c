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

static CURLcode test_lib544(const char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  static const char teststring_init[] = {
    'T', 'h', 'i', 's', '\0', ' ', 'i', 's', ' ', 't', 'e', 's', 't', ' ',
    'b', 'i', 'n', 'a', 'r', 'y', ' ', 'd', 'a', 't', 'a', ' ',
    'w', 'i', 't', 'h', ' ', 'a', 'n', ' ',
    'e', 'm', 'b', 'e', 'd', 'd', 'e', 'd', ' ', 'N', 'U', 'L'};

  char teststring[sizeof(teststring_init)];

  memcpy(teststring, teststring_init, sizeof(teststring_init));

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  if(testnum == 545)
    test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sizeof(teststring));

  test_setopt(curl, CURLOPT_COPYPOSTFIELDS, teststring);

  test_setopt(curl, CURLOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(curl, CURLOPT_HEADER, 1L); /* include header */

  /* Update the original data to detect non-copy. */
  strcpy(teststring, "FAIL");

  {
    CURL *handle2;
    handle2 = curl_easy_duphandle(curl);
    curl_easy_cleanup(curl);

    curl = handle2;
  }

  /* Now, this is a POST request with binary 0 embedded in POST data. */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
