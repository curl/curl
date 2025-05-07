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
  CURLcode res = CURLE_OK;
  char *url_after = NULL;
  CURLU *curlu = curl_url();
  char error_buffer[CURL_ERROR_SIZE] = "";
  CURL *curl;

  easy_init(curl);

  curl_url_set(curlu, CURLUPART_URL, URL, CURLU_DEFAULT_SCHEME);
  easy_setopt(curl, CURLOPT_CURLU, curlu);
  easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  /* msys2 times out instead of CURLE_COULDNT_CONNECT, so make it faster */
  easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
  /* set a port number that makes this request fail */
  easy_setopt(curl, CURLOPT_PORT, 1L);
  res = curl_easy_perform(curl);
  if(res != CURLE_COULDNT_CONNECT && res != CURLE_OPERATION_TIMEDOUT) {
    curl_mfprintf(stderr, "failure expected, "
                  "curl_easy_perform returned %d: <%s>, <%s>\n",
                  res, curl_easy_strerror(res), error_buffer);
    if(res == CURLE_OK)
      res = TEST_ERR_MAJOR_BAD;  /* force an error return */
    goto test_cleanup;
  }
  res = CURLE_OK;  /* reset for next use */

  /* print the used url */
  curl_url_get(curlu, CURLUPART_URL, &url_after, 0);
  curl_mfprintf(stderr, "curlu now: <%s>\n", url_after);
  curl_free(url_after);
  url_after = NULL;

  /* now reset CURLOP_PORT to go back to originally set port number */
  easy_setopt(curl, CURLOPT_PORT, 0L);

  res = curl_easy_perform(curl);
  if(res)
    curl_mfprintf(stderr, "success expected, "
                  "curl_easy_perform returned %d: <%s>, <%s>\n",
                  res, curl_easy_strerror(res), error_buffer);

  /* print url */
  curl_url_get(curlu, CURLUPART_URL, &url_after, 0);
  curl_mfprintf(stderr, "curlu now: <%s>\n", url_after);

test_cleanup:
  curl_free(url_after);
  curl_easy_cleanup(curl);
  curl_url_cleanup(curlu);
  curl_global_cleanup();

  return res;
}
