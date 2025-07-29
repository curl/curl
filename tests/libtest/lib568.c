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

#include "testutil.h"
#include "memdebug.h"

/*
 * Test the Client->Server ANNOUNCE functionality (PUT style)
 */
static CURLcode test_lib568(char *URL)
{
  CURLcode res;
  CURL *curl;
  int sdp;
  FILE *sdpf = NULL;
  struct_stat file_info;
  char *stream_uri = NULL;
  int request = 1;
  struct curl_slist *custom_headers = NULL;

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

  test_setopt(curl, CURLOPT_HEADERDATA, stdout);
  test_setopt(curl, CURLOPT_WRITEDATA, stdout);

  test_setopt(curl, CURLOPT_URL, URL);

  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  sdp = open(libtest_arg2, O_RDONLY);
  if(sdp == -1) {
    curl_mfprintf(stderr, "can't open %s\n", libtest_arg2);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  fstat(sdp, &file_info);
  close(sdp);

  sdpf = fopen(libtest_arg2, "rb");
  if(!sdpf) {
    curl_mfprintf(stderr, "can't fopen %s\n", libtest_arg2);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_ANNOUNCE);

  test_setopt(curl, CURLOPT_READDATA, sdpf);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) file_info.st_size);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* Do the ANNOUNCE */
  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  test_setopt(curl, CURLOPT_UPLOAD, 0L);
  fclose(sdpf);
  sdpf = NULL;

  /* Make sure we can do a normal request now */
  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_DESCRIBE);
  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  /* Now do a POST style one */

  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  custom_headers = curl_slist_append(custom_headers,
                                     "Content-Type: posty goodness");
  if(!custom_headers) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSPHEADER, custom_headers);
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_ANNOUNCE);
  test_setopt(curl, CURLOPT_POSTFIELDS,
              "postyfield=postystuff&project=curl\n");

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  test_setopt(curl, CURLOPT_POSTFIELDS, NULL);
  test_setopt(curl, CURLOPT_RTSPHEADER, NULL);
  curl_slist_free_all(custom_headers);
  custom_headers = NULL;

  /* Make sure we can do a normal request now */
  stream_uri = tutil_suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  res = curl_easy_perform(curl);

test_cleanup:

  if(sdpf)
    fclose(sdpf);

  curl_free(stream_uri);

  if(custom_headers)
    curl_slist_free_all(custom_headers);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
