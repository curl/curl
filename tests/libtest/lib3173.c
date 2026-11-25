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

#include "testtrace.h"

static CURLcode test_lib3173(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  CURL *d = NULL;
  curl_mime *m = NULL;
  struct curl_slist *hd = NULL;
  struct curl_slist *rc = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  m = curl_mime_init(curl);
  curl_mime_data(curl_mime_addpart(m), "hello body\r\n", CURL_ZERO_TERMINATED);
  hd = curl_slist_append(NULL, "Subject: first-list-header");
  rc = curl_slist_append(NULL, "<b@x>");
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_USERPWD, "u:p");
  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<a@x>");
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, rc);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hd);
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, m);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  result = curl_easy_perform(curl);

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);   /* done with the list */
  curl_slist_free_all(hd);
  d = curl_easy_duphandle(curl);
  curl_easy_cleanup(d);
  curl_mime_free(m);
  curl_slist_free_all(rc);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
