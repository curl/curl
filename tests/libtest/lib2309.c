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
#include "testtrace.h"

#include <curl/curl.h>

static size_t cb_ignore(char *buffer, size_t size, size_t nmemb, void *userp)
{
  (void)buffer;
  (void)size;
  (void)nmemb;
  (void)userp;
  return CURL_WRITEFUNC_ERROR;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURL *curldupe;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_ignore);
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY, libtest_arg3);
    curl_easy_setopt(curl, CURLOPT_NETRC, (long)CURL_NETRC_REQUIRED);
    curl_easy_setopt(curl, CURLOPT_NETRC_FILE, libtest_arg2);

    curldupe = curl_easy_duphandle(curl);
    if(curldupe) {
      res = curl_easy_perform(curldupe);
      curl_mprintf("Returned %d, should be %d.\n", res, CURLE_WRITE_ERROR);
      fflush(stdout);
      curl_easy_cleanup(curldupe);
    }
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return CURLE_OK;
}
