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
#include "test.h"

#include "memdebug.h"

static char testbuf[17000]; /* more than 16K */

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  CURLFORMcode formrc;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;

  /* create a buffer with AAAA...BBBBB...CCCC...etc */
  int i;
  int size = (int)sizeof(testbuf)/1000;

  for(i = 0; i < size ; i++)
    memset(&testbuf[i * 1000], 65 + i, 1000);

  testbuf[sizeof(testbuf)-1] = 0; /* null-terminate */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  CURL_IGNORE_DEPRECATION(
    /* Check proper name and data copying. */
    formrc = curl_formadd(&formpost, &lastptr,
                          CURLFORM_COPYNAME, "hello",
                          CURLFORM_COPYCONTENTS, testbuf,
                          CURLFORM_END);
  )
  if(formrc)
    printf("curl_formadd(1) = %d\n", (int) formrc);


  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    CURL_IGNORE_DEPRECATION(
      curl_formfree(formpost);
    )
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  CURL_IGNORE_DEPRECATION(
    /* send a multi-part formpost */
    test_setopt(curl, CURLOPT_HTTPPOST, formpost);
  )

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  CURL_IGNORE_DEPRECATION(
    /* now cleanup the formpost chain */
    curl_formfree(formpost);
  )

  curl_global_cleanup();

  return res;
}
