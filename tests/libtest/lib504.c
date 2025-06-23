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

/*
 * Source code in here hugely as reported in bug report 651464 by
 * Christopher R. Palmer.
 *
 * Use multi interface to get document over proxy with bad port number.
 * This caused the interface to "hang" in libcurl 7.10.2.
 */
static CURLcode test_lib504(char *URL)
{
  CURL *c = NULL;
  CURLcode res = CURLE_OK;
  CURLM *m = NULL;
  fd_set rd, wr, exc;
  int running;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(c);

  /* The point here is that there must not be anything running on the given
     proxy port */
  if(libtest_arg2)
    easy_setopt(c, CURLOPT_PROXY, libtest_arg2);
  easy_setopt(c, CURLOPT_URL, URL);
  easy_setopt(c, CURLOPT_VERBOSE, 1L);

  multi_init(m);

  multi_add_handle(m, c);

  for(;;) {
    struct timeval interval;
    int maxfd = -99;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    curl_mfprintf(stderr, "curl_multi_perform()\n");

    multi_perform(m, &running);

    while(running) {
      CURLMcode mres;
      int num;
      mres = curl_multi_wait(m, NULL, 0, TEST_HANG_TIMEOUT, &num);
      if(mres != CURLM_OK) {
        curl_mprintf("curl_multi_wait() returned %d\n", mres);
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }

      abort_on_test_timeout();
      multi_perform(m, &running);
      abort_on_test_timeout();
    }

    abort_on_test_timeout();

    if(!running) {
      /* This is where this code is expected to reach */
      int numleft;
      CURLMsg *msg = curl_multi_info_read(m, &numleft);
      curl_mfprintf(stderr, "Expected: not running\n");
      if(msg && !numleft)
        res = TEST_ERR_SUCCESS; /* this is where we should be */
      else
        res = TEST_ERR_FAILURE; /* not correct */
      break; /* done */
    }
    curl_mfprintf(stderr, "running == %d\n", running);

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    curl_mfprintf(stderr, "curl_multi_fdset()\n");

    multi_fdset(m, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PA */

  curl_multi_remove_handle(m, c);
  curl_multi_cleanup(m);
  curl_easy_cleanup(c);
  curl_global_cleanup();

  return res;
}
