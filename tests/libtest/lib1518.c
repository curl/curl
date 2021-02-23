/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

/* Test inspired by github issue 3340 */

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  long curlResponseCode;
  long curlRedirectCount;
  char *effectiveUrl = NULL;
  char *redirectUrl = NULL;

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  /* just to make it explicit and visible in this test: */
  test_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curlResponseCode);
  curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &curlRedirectCount);
  curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effectiveUrl);
  curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirectUrl);

  printf("res: %d\n"
         "status: %d\n"
         "redirects: %d\n"
         "effectiveurl: %s\n"
         "redirecturl: %s\n",
         (int)res,
         (int)curlResponseCode,
         (int)curlRedirectCount,
         effectiveUrl,
         redirectUrl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
