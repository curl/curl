/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Dmitry Karpov <dkarpov1970@gmail.com>
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

static CURLcode test_lib2412(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURLM *multi = NULL;
  CURL *easy = NULL;
  CURLMcode rc;
  fd_set readFdSet, writeFdSet, exceptFdSet;
  int maxFd;

  (void)URL;
  global_init(CURL_GLOBAL_ALL);

  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy = curl_easy_init();
  if(!easy) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  easy_setopt(easy, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(easy, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  rc = curl_multi_add_handle(multi, easy);
  if(rc) {
    curl_mfprintf(stderr, "curl_multi_add_handle() failed: %d\n", rc);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  FD_ZERO(&readFdSet);
  FD_ZERO(&writeFdSet);
  FD_ZERO(&exceptFdSet);
  maxFd = -1;
  rc = curl_multi_fdset(multi, &readFdSet, &writeFdSet, &exceptFdSet,
                        &maxFd);
  if(rc) {
    curl_mfprintf(stderr, "curl_multi_fdset() failed: %d\n", rc);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  if(maxFd == -1)
    curl_mfprintf(stderr, "There are no file descriptors to wait for\n");
  else {
    curl_mfprintf(stderr, "libcurl supplied a file descriptor to "
           "wait for (maxFd=%d).  Waiting now ...\n", maxFd);
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  if(easy) {
    curl_multi_remove_handle(multi, easy);
    curl_easy_cleanup(easy);
  }
  if(multi)
    curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
}
