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

#include "memdebug.h"

static char t1576_testdata[] = "request indicates that the client, which made";

static size_t t1576_read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t amount = nmemb * size; /* Total bytes curl wants */
  if(amount < strlen(t1576_testdata)) {
    return strlen(t1576_testdata);
  }
  (void)stream;
  memcpy(ptr, t1576_testdata, strlen(t1576_testdata));
  return strlen(t1576_testdata);
}

static int t1576_seek_callback(void *ptr, curl_off_t offset, int origin)
{
  (void)ptr;
  (void)offset;
  if(origin != SEEK_SET)
    return CURL_SEEKFUNC_FAIL;
  return CURL_SEEKFUNC_OK;
}

static CURLcode test_lib1576(const char *URL)
{
  CURLcode res;
  CURL *curl;
  struct curl_slist *pHeaderList = NULL;

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

  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_READFUNCTION, t1576_read_cb);
  test_setopt(curl, CURLOPT_SEEKFUNCTION, t1576_seek_callback);
  test_setopt(curl, CURLOPT_INFILESIZE, (long)strlen(t1576_testdata));

  test_setopt(curl, CURLOPT_CUSTOMREQUEST, "CURL");
  if(testnum == 1578 || testnum == 1580) {
    test_setopt(curl, CURLOPT_FOLLOWLOCATION, CURLFOLLOW_FIRSTONLY);
  }
  else {
    test_setopt(curl, CURLOPT_FOLLOWLOCATION, CURLFOLLOW_OBEYCODE);
  }
  /* Remove "Expect: 100-continue" */
  pHeaderList = curl_slist_append(pHeaderList, "Expect:");

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pHeaderList);
  res = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl_slist_free_all(pHeaderList);

  return res;
}
