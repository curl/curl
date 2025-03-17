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
#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 30 * 1000

/* 500 milliseconds allowed. An extreme number but lets be really conservative
   to allow old and slow machines to run this test too */
#define MAX_BLOCKED_TIME_MS 500

CURLcode test(char *URL)
{
  CURL *handle = NULL;
  CURLM *mhandle = NULL;
  CURLcode res = CURLE_OK;
  int still_running = 0;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(handle);

  easy_setopt(handle, CURLOPT_URL, URL);
  easy_setopt(handle, CURLOPT_VERBOSE, 1L);

  multi_init(mhandle);

  multi_add_handle(mhandle, handle);

  multi_perform(mhandle, &still_running);

  abort_on_test_timeout();

  while(still_running) {
    struct timeval timeout;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -99;
    struct timeval before;
    struct timeval after;
    long e;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000L; /* 100 ms */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    multi_fdset(mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    abort_on_test_timeout();

    fprintf(stderr, "ping\n");
    before = tutil_tvnow();

    multi_perform(mhandle, &still_running);

    abort_on_test_timeout();

    after = tutil_tvnow();
    e = tutil_tvdiff(after, before);
    fprintf(stderr, "pong = %ld\n", e);

    if(e > MAX_BLOCKED_TIME_MS) {
      res = CURLE_TOO_LARGE;
      break;
    }
  }

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(mhandle);
  curl_easy_cleanup(handle);
  curl_global_cleanup();

  return res;
}
