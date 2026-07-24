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
 * A CR or LF in an RTSP stream URI, Transport or Session ID must be rejected
 * before the request is put on the control stream, otherwise the byte splits
 * the request line/header and smuggles a second request.
 */
static CURLcode test_lib657(const char *URL)
{
  CURLcode result = TEST_ERR_MAJOR_BAD;
  CURL *curl;

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

  easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
  easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  easy_setopt(curl, CURLOPT_URL, URL);

  /* a plain OPTIONS so the control connection is set up and the happy path is
     exercised */
  easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, URL);
  easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* CRLF in the stream URI must be refused */
  easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,
              "rtsp://example/\r\nOPTIONS rtsp://evil/ RTSP/1.0");
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "control byte in stream URI not rejected: %d\n",
                  (int)result);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* CRLF in the Transport header must be refused */
  easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, URL);
  easy_setopt(curl, CURLOPT_RTSP_TRANSPORT,
              "RAW/RAW/UDP;unicast\r\nInjected: 1");
  easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "control byte in transport not rejected: %d\n",
                  (int)result);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* CRLF in the Session ID must be refused */
  easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, URL);
  easy_setopt(curl, CURLOPT_RTSP_SESSION_ID, "1234\r\nInjected: 1");
  easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_PLAY);
  result = curl_easy_perform(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "control byte in session ID not rejected: %d\n",
                  (int)result);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  result = CURLE_OK;

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
