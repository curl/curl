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

/*
 * Test Session ID capture
 */
static CURLcode test_lib569(const char *URL)
{
  CURLcode result;
  CURL *curl;
  CURL *clone = NULL;
  struct curl_slist *resolve = NULL;
  char *stream_uri = NULL;
  int request = 1;
  int i;

  FILE *idfile = curlx_fopen(libtest_arg2, "wb");
  if(!idfile) {
    curl_mfprintf(stderr, "Could not open the Session ID File\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    curlx_fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    curlx_fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
  easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_URL, URL);

  easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "This should have failed. "
                  "Cannot setup without a Transport: header");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Go through the various Session IDs */
  for(i = 0; i < 3; i++) {
    const char *rtsp_session_id;
    stream_uri = tutil_suburl(URL, request++);
    if(!stream_uri) {
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
    curl_free(stream_uri);
    stream_uri = NULL;

    easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
    easy_setopt(curl, CURLOPT_RTSP_TRANSPORT,
                "Fake/NotReal/JustATest;foo=baz");
    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;

    curl_easy_getinfo(curl, CURLINFO_RTSP_SESSION_ID, &rtsp_session_id);
    curl_mfprintf(idfile, "Got Session ID: [%s]\n", rtsp_session_id);
    rtsp_session_id = NULL;

    stream_uri = tutil_suburl(URL, request++);
    if(!stream_uri) {
      result = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
    curl_free(stream_uri);
    stream_uri = NULL;

    easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_TEARDOWN);
    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;

    /* Clear for the next go-round, retaining the final ID for the clone. */
    if(i < 2)
      easy_setopt(curl, CURLOPT_RTSP_SESSION_ID, NULL);
  }

  /* A clone must not send the learned Session ID to another origin. */
  clone = curl_easy_duphandle(curl);
  resolve = curl_slist_append(NULL, libtest_arg4);
  if(!clone || !resolve) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  easy_setopt(clone, CURLOPT_RESOLVE, resolve);
  easy_setopt(clone, CURLOPT_URL, libtest_arg3);
  easy_setopt(clone, CURLOPT_RTSP_STREAM_URI, libtest_arg3);
  easy_setopt(clone, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  result = curl_easy_perform(clone);

test_cleanup:

  if(idfile)
    curlx_fclose(idfile);

  curl_free(stream_uri);
  curl_easy_cleanup(clone);
  curl_slist_free_all(resolve);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
