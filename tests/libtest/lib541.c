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
 * Two FTP uploads, the second with no content sent.
 */

static CURLcode test_lib541(const char *URL)
{
  CURL *curl;
  CURLcode result = CURLE_OK;
  char errbuf[STRERROR_LEN];
  FILE *hd_src;
  int hd;
  curl_struct_stat file_info;

  if(!libtest_arg2) {
    curl_mfprintf(stderr, "Usage: <url> <file-to-upload>\n");
    return TEST_ERR_USAGE;
  }

  hd_src = curlx_fopen(libtest_arg2, "rb");
  if(!hd_src) {
    curl_mfprintf(stderr, "fopen() failed with error (%d) %s\n",
                  errno, curlx_strerror(errno, errbuf, sizeof(errbuf)));
    curl_mfprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    return TEST_ERR_MAJOR_BAD; /* if this happens things are major weird */
  }

  /* get the file size of the local file */
  hd = curlx_fstat(fileno(hd_src), &file_info);
  if(hd == -1) {
    /* cannot open file, bail out */
    curl_mfprintf(stderr, "fstat() failed with error (%d) %s\n",
                  errno, curlx_strerror(errno, errbuf, sizeof(errbuf)));
    curl_mfprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    curlx_fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  if(!file_info.st_size) {
    curl_mfprintf(stderr, "File %s has zero size!\n", libtest_arg2);
    curlx_fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    curlx_fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  /* get a curl handle */
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    curlx_fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  /* enable uploading */
  test_setopt(curl, CURLOPT_UPLOAD, 1L);

  /* enable verbose */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* specify target */
  test_setopt(curl, CURLOPT_URL, URL);

  /* now specify which file to upload */
  test_setopt(curl, CURLOPT_READDATA, hd_src);

  /* Now run off and do what you have been told! */
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  /* and now upload the exact same again, but without rewinding so it already
     is at end of file */
  result = curl_easy_perform(curl);

test_cleanup:

  /* close the local file */
  curlx_fclose(hd_src);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
