/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

int test(char *URL)
{
  char *url_after;
  CURLU *curlu = curl_url();
  CURL *curl = curl_easy_init();
  CURLcode curl_code;
  char error_buffer[CURL_ERROR_SIZE] = "";

  curl_url_set(curlu, CURLUPART_URL, URL, CURLU_DEFAULT_SCHEME);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  /* set a port number that makes this request fail */
  curl_easy_setopt(curl, CURLOPT_PORT, 1L);
  curl_code = curl_easy_perform(curl);
  if(!curl_code)
    fprintf(stderr, "failure expected, "
            "curl_easy_perform returned %ld: <%s>, <%s>\n",
            (long) curl_code, curl_easy_strerror(curl_code), error_buffer);

  /* print the used url */
  curl_url_get(curlu, CURLUPART_URL, &url_after, 0);
  fprintf(stderr, "curlu now: <%s>\n", url_after);
  curl_free(url_after);

  /* now reset CURLOP_PORT to go back to originally set port number */
  curl_easy_setopt(curl, CURLOPT_PORT, 0L);

  curl_code = curl_easy_perform(curl);
  if(curl_code)
    fprintf(stderr, "success expected, "
            "curl_easy_perform returned %ld: <%s>, <%s>\n",
            (long) curl_code, curl_easy_strerror(curl_code), error_buffer);

  /* print url */
  curl_url_get(curlu, CURLUPART_URL, &url_after, 0);
  fprintf(stderr, "curlu now: <%s>\n", url_after);
  curl_free(url_after);

  curl_easy_cleanup(curl);
  curl_url_cleanup(curlu);
  curl_global_cleanup();

  return 0;
}
