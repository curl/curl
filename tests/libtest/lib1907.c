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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

CURLcode test(char *URL)
{
  char *url_after;
  CURL *curl;
  CURLcode res = CURLE_OK;
  char error_buffer[CURL_ERROR_SIZE] = "";

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  res = curl_easy_perform(curl);
  if(!res)
    fprintf(stderr, "failure expected, "
            "curl_easy_perform returned %ld: <%s>, <%s>\n",
            (long) res, curl_easy_strerror(res), error_buffer);

  /* print the used url */
  if(!curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url_after))
    printf("Effective URL: %s\n", url_after);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
