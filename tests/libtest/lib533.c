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
/* used for test case 533, 534, 535 and 546 */

#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  int running;
  CURLM *m = NULL;
  int current = 0;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

  multi_init(m);

  multi_add_handle(m, curl);

  fprintf(stderr, "Start at URL 0\n");

  for(;;) {
    struct timeval interval;
    fd_set rd, wr, exc;
    int maxfd = -99;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    multi_perform(m, &running);

    abort_on_test_timeout();

    if(!running) {
      if(!current++) {
        fprintf(stderr, "Advancing to URL 1\n");
        /* remove the handle we use */
        curl_multi_remove_handle(m, curl);

        /* make us reuse the same handle all the time, and try resetting
           the handle first too */
        curl_easy_reset(curl);
        easy_setopt(curl, CURLOPT_URL, libtest_arg2);
        easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

        /* re-add it */
        multi_add_handle(m, curl);
      }
      else
        break; /* done */
    }

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    multi_fdset(m, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

  /* undocumented cleanup sequence - type UB */

  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();

  return res;
}
