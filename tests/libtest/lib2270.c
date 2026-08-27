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

static CURLcode test_lib2270(const char *URL)
{
  CURL *curl = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;
  CURLFORMcode formrc;
  CURLcode result = TEST_ERR_MAJOR_BAD;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    goto test_cleanup;
  }

  mime = curl_mime_init(curl);
  if(!mime) {
    curl_mfprintf(stderr, "curl_mime_init() failed\n");
    goto test_cleanup;
  }
  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart() failed\n");
    goto test_cleanup;
  }
  result = curl_mime_name(part, "field");
  if(result)
    goto test_cleanup;
  result = curl_mime_data(part, "value", CURL_ZERO_TERMINATED);
  if(result)
    goto test_cleanup;

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_MIMEPOST, mime);
  easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)1);
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "MIME resume returned %d, expected %d\n",
                  (int)result, CURLE_BAD_FUNCTION_ARGUMENT);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  easy_setopt(curl, CURLOPT_MIMEPOST, NULL);
  formrc = curl_formadd(&formpost, &lastptr,
                        CURLFORM_COPYNAME, "field",
                        CURLFORM_COPYCONTENTS, "value",
                        CURLFORM_END);
  if(formrc) {
    curl_mfprintf(stderr, "curl_formadd() failed with code %d\n",
                  (int)formrc);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
  easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)-1);
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "form resume returned %d, expected %d\n",
                  (int)result, CURLE_BAD_FUNCTION_ARGUMENT);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  result = CURLE_OK;

test_cleanup:
  curl_easy_cleanup(curl);
  curl_mime_free(mime);
  curl_formfree(formpost);
  curl_global_cleanup();
  return result;
}
