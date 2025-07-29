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

static CURLcode test_lib666(char *URL)
{
  static char testbuf[17000]; /* more than 16K */

  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  curl_mime *mime = NULL;
  curl_mimepart *part;
  size_t i;

  /* Checks huge binary-encoded mime post. */

  /* Create a testbuf with pseudo-binary data. */
  for(i = 0; i < sizeof(testbuf); i++)
    if(i % 77 == 76)
      testbuf[i] = '\n';
    else
      testbuf[i] = (char) (0x41 + i % 26); /* A...Z */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Build mime structure. */
  mime = curl_mime_init(curl);
  if(!mime) {
    curl_mfprintf(stderr, "curl_mime_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  res = curl_mime_name(part, "upfile");
  if(res) {
    curl_mfprintf(stderr, "curl_mime_name() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_filename(part, "myfile.txt");
  if(res) {
    curl_mfprintf(stderr, "curl_mime_filename() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_data(part, testbuf, sizeof(testbuf));
  if(res) {
    curl_mfprintf(stderr, "curl_mime_data() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_encoder(part, "binary");
  if(res) {
    curl_mfprintf(stderr, "curl_mime_encoder() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our mime mail. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* Post form */
  test_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* Shorten upload buffer. */
  test_setopt(curl, CURLOPT_UPLOAD_BUFFERSIZE, 16411L);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  /* now cleanup the mime structure */
  curl_mime_free(mime);

  curl_global_cleanup();

  return res;
}
