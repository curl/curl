/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

static char teststring[] =
#ifdef CURL_DOES_CONVERSIONS
  /* ASCII representation with escape sequences for non-ASCII platforms */
  "\x54\x68\x69\x73\x00\x20\x69\x73\x20\x74\x65\x73\x74\x20\x62\x69\x6e\x61"
  "\x72\x79\x20\x64\x61\x74\x61\x20\x77\x69\x74\x68\x20\x61\x6e\x20\x65\x6d"
  "\x62\x65\x64\x64\x65\x64\x20\x4e\x55\x4c\x20\x62\x79\x74\x65\x0a";
#else
{   'T', 'h', 'i', 's', '\0', ' ', 'i', 's', ' ', 't', 'e', 's', 't', ' ',
    'b', 'i', 'n', 'a', 'r', 'y', ' ', 'd', 'a', 't', 'a', ' ',
    'w', 'i', 't', 'h', ' ', 'a', 'n', ' ',
    'e', 'm', 'b', 'e', 'd', 'd', 'e', 'd', ' ', 'N', 'U', 'L'};
#endif


int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

#ifdef LIB545
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) sizeof teststring);
#endif

  test_setopt(curl, CURLOPT_COPYPOSTFIELDS, teststring);

  test_setopt(curl, CURLOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(curl, CURLOPT_HEADER, 1L); /* include header */

  /* Update the original data to detect non-copy. */
  strcpy(teststring, "FAIL");

#ifdef LIB545
  {
    CURL *handle2;
    handle2 = curl_easy_duphandle(curl);
    curl_easy_cleanup(curl);

    curl = handle2;
  }
#endif

  /* Now, this is a POST request with binary 0 embedded in POST data. */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
