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

static char data[]="this is what we post to the silly web server\n";

struct WriteThis {
  char *readptr;
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  size_t tocopy = size * nmemb;

  /* Wait one second before return POST data          *
   * so libcurl will wait before sending request body */
  wait_ms(1000);

  if(tocopy < 1 || !pooh->sizeleft)
    return 0;

  if(pooh->sizeleft < tocopy)
    tocopy = pooh->sizeleft;

  memcpy(ptr, pooh->readptr, tocopy);/* copy requested data */
  pooh->readptr += tocopy;           /* advance pointer */
  pooh->sizeleft -= tocopy;          /* less data left */
  return tocopy;
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  struct WriteThis pooh;

  if(!strcmp(URL, "check")) {
#if (defined(WIN32) || defined(__CYGWIN__))
    printf("Windows TCP does not deliver response data but reports "
           "CONNABORTED\n");
    return 1; /* skip since test will fail on Windows without workaround */
#else
    return 0; /* sure, run this! */
#endif
  }

  pooh.readptr = data;
  pooh.sizeleft = strlen(data);

  if(curl_global_init(CURL_GLOBAL_ALL)) {
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

  /* Now specify we want to POST data */
  test_setopt(curl, CURLOPT_POST, 1L);

  /* Set the expected POST size */
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)pooh.sizeleft);

  /* we want to use our own read function */
  test_setopt(curl, CURLOPT_READFUNCTION, read_callback);

  /* pointer to pass to our read function */
  test_setopt(curl, CURLOPT_READDATA, &pooh);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* detect HTTP error codes >= 400 */
  /* test_setopt(curl, CURLOPT_FAILONERROR, 1L); */


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
