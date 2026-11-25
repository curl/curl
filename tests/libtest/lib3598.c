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
#include "unitcheck.h"

static CURLcode test_lib3598(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_MIME) && !defined(CURL_DISABLE_HTTP)

  CURL *curl = NULL;
  CURL *dup = NULL;
  CURLcode result = CURLE_OK;
  struct curl_slist *headers = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  fail_unless(curl != NULL, "curl_easy_init() failed");

  headers = curl_slist_append(NULL, "X-Custom: yes");
  fail_unless(headers != NULL, "curl_slist_append failed");

  mime = curl_mime_init(curl);
  fail_unless(mime != NULL, "curl_mime_init failed");
  part = curl_mime_addpart(mime);
  fail_unless(part != NULL, "curl_mime_addpart failed");
  result = curl_mime_name(part, "a\r\nb");
  fail_unless(result == CURLE_OK, "curl_mime_name failed");
  result = curl_mime_data(part, "x", CURL_ZERO_TERMINATED);
  fail_unless(result == CURLE_OK, "curl_mime_data failed");

  result = curl_easy_setopt(curl, CURLOPT_URL, arg);
  fail_unless(result == CURLE_OK, "CURLOPT_URL failed");
  result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  fail_unless(result == CURLE_OK, "CURLOPT_HTTPHEADER failed");
  result = curl_easy_setopt(curl, CURLOPT_MIME_OPTIONS,
                            (long)CURLMIMEOPT_FORMESCAPE);
  fail_unless(result == CURLE_OK, "CURLOPT_MIME_OPTIONS failed");
  result = curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
  fail_unless(result == CURLE_OK, "CURLOPT_MIMEPOST failed");

  result = curl_easy_perform(curl);
  fail_unless(result == CURLE_BAD_FUNCTION_ARGUMENT,
              "CRLF in escaped part name did not fail the transfer");

  result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
  fail_unless(result == CURLE_OK, "clearing CURLOPT_HTTPHEADER failed");
  curl_slist_free_all(headers);

  dup = curl_easy_duphandle(curl);
  fail_unless(dup != NULL,
              "curl_easy_duphandle failed after released header list");

  curl_easy_cleanup(dup);
  curl_easy_cleanup(curl);
  curl_mime_free(mime);
  curl_global_cleanup();
#else
  (void)arg;
#endif

  UNITTEST_END_SIMPLE
}
