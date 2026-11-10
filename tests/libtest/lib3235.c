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

/* A duplicated RTSP handle must retain where its Session ID was learned. */
static CURLcode test_lib3235(const char *URL)
{
  CURL *source = NULL;
  CURL *cross = NULL;
  CURL *same = NULL;
  CURL *explicit_id = NULL;
  CURL *redirect = NULL;
  struct curl_slist *resolve = NULL;
  const char *session_id = NULL;
  char *a1 = NULL;
  char *b2 = NULL;
  char *a3 = NULL;
  char *b4 = NULL;
  char *a5 = NULL;
  CURLcode result = CURLE_OK;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
    return TEST_ERR_MAJOR_BAD;

  a1 = tutil_suburl(URL, 1);
  b2 = tutil_suburl(libtest_arg2, 2);
  a3 = tutil_suburl(URL, 3);
  b4 = tutil_suburl(libtest_arg2, 4);
  a5 = tutil_suburl(URL, 5);
  resolve = curl_slist_append(NULL, libtest_arg3);
  if(!a1 || !b2 || !a3 || !b4 || !a5 || !resolve) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy_init(source);
  easy_setopt(source, CURLOPT_URL, a1);
  easy_setopt(source, CURLOPT_RTSP_STREAM_URI, a1);
  easy_setopt(source, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  easy_setopt(source, CURLOPT_RESOLVE, resolve);
  easy_setopt(source, CURLOPT_HEADERDATA, stdout);
  easy_setopt(source, CURLOPT_WRITEDATA, stdout);
  easy_setopt(source, CURLOPT_VERBOSE, 1L);

  result = curl_easy_perform(source);
  if(result)
    goto test_cleanup;

  result = curl_easy_getinfo(source, CURLINFO_RTSP_SESSION_ID, &session_id);
  if(result)
    goto test_cleanup;
  if(!session_id || strcmp(session_id, "LEARNED-ID")) {
    curl_mfprintf(stderr, "RTSP Session ID was not learned\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  cross = curl_easy_duphandle(source);
  same = curl_easy_duphandle(source);
  explicit_id = curl_easy_duphandle(source);
  redirect = curl_easy_duphandle(source);
  if(!cross || !same || !explicit_id || !redirect) {
    curl_mfprintf(stderr, "curl_easy_duphandle() failed\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* The clones must retain the origin after the source is destroyed. */
  curl_easy_cleanup(source);
  source = NULL;

  easy_setopt(cross, CURLOPT_URL, b2);
  easy_setopt(cross, CURLOPT_RTSP_STREAM_URI, b2);
  result = curl_easy_perform(cross);
  if(result)
    goto test_cleanup;

  easy_setopt(same, CURLOPT_URL, a3);
  easy_setopt(same, CURLOPT_RTSP_STREAM_URI, a3);
  result = curl_easy_perform(same);
  if(result)
    goto test_cleanup;

  /* An ID supplied by the application is not bound to the learned origin. */
  easy_setopt(explicit_id, CURLOPT_RTSP_SESSION_ID, "APP-SET-ID");
  easy_setopt(explicit_id, CURLOPT_URL, b4);
  easy_setopt(explicit_id, CURLOPT_RTSP_STREAM_URI, b4);
  result = curl_easy_perform(explicit_id);
  if(result)
    goto test_cleanup;

  /* A redirect on a clone must also suppress the learned ID at B. */
  easy_setopt(redirect, CURLOPT_URL, a5);
  easy_setopt(redirect, CURLOPT_RTSP_STREAM_URI, a5);
  easy_setopt(redirect, CURLOPT_FOLLOWLOCATION, 1L);
  easy_setopt(redirect, CURLOPT_REDIR_PROTOCOLS_STR, "rtsp");
  result = curl_easy_perform(redirect);

test_cleanup:
  curl_easy_cleanup(redirect);
  curl_easy_cleanup(explicit_id);
  curl_easy_cleanup(same);
  curl_easy_cleanup(cross);
  curl_easy_cleanup(source);
  curl_slist_free_all(resolve);
  curl_free(b4);
  curl_free(a5);
  curl_free(a3);
  curl_free(b2);
  curl_free(a1);
  curl_global_cleanup();
  return result;
}
