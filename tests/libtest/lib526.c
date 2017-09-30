/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * This code sets up multiple easy handles that transfer a single file from
 * the same URL, in a serial manner after each other. Due to the connection
 * sharing within the multi handle all transfers are performed on the same
 * persistent connection.
 *
 * This source code is used for lib526, lib527 and lib532 with only #ifdefs
 * controlling the small differences.
 *
 * - lib526 closes all easy handles after
 *   they all have transferred the file over the single connection
 * - lib527 closes each easy handle after each single transfer.
 * - lib532 uses only a single easy handle that is removed, reset and then
 *   re-added for each transfer
 *
 * Test case 526, 527 and 532 use FTP, while test 528 uses the lib526 tool but
 * with HTTP.
 */

#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

#define NUM_HANDLES 4

int test(char *URL)
{
  int res = 0;
  CURL *curl[NUM_HANDLES];
  int running;
  CURLM *m = NULL;
  int current = 0;
  int i;

  for(i = 0; i < NUM_HANDLES; i++)
    curl[i] = NULL;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  /* get NUM_HANDLES easy handles */
  for(i = 0; i < NUM_HANDLES; i++) {
    easy_init(curl[i]);
    /* specify target */
    easy_setopt(curl[i], CURLOPT_URL, URL);
    /* go verbose */
    easy_setopt(curl[i], CURLOPT_VERBOSE, 1L);
  }

  multi_init(m);

  multi_add_handle(m, curl[current]);

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
#ifdef LIB527
      /* NOTE: this code does not remove the handle from the multi handle
         here, which would be the nice, sane and documented way of working.
         This however tests that the API survives this abuse gracefully. */
      curl_easy_cleanup(curl[current]);
      curl[current] = NULL;
#endif
      if(++current < NUM_HANDLES) {
        fprintf(stderr, "Advancing to URL %d\n", current);
#ifdef LIB532
        /* first remove the only handle we use */
        curl_multi_remove_handle(m, curl[0]);

        /* make us re-use the same handle all the time, and try resetting
           the handle first too */
        curl_easy_reset(curl[0]);
        easy_setopt(curl[0], CURLOPT_URL, URL);
        /* go verbose */
        easy_setopt(curl[0], CURLOPT_VERBOSE, 1L);

        /* re-add it */
        multi_add_handle(m, curl[0]);
#else
        multi_add_handle(m, curl[current]);
#endif
      }
      else {
        break; /* done */
      }
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

#if defined(LIB526)

  /* test 526 and 528 */
  /* proper cleanup sequence - type PB */

  for(i = 0; i < NUM_HANDLES; i++) {
    curl_multi_remove_handle(m, curl[i]);
    curl_easy_cleanup(curl[i]);
  }
  curl_multi_cleanup(m);
  curl_global_cleanup();

#elif defined(LIB527)

  /* test 527 */

  /* Upon non-failure test flow the easy's have already been cleanup'ed. In
     case there is a failure we arrive here with easy's that have not been
     cleanup'ed yet, in this case we have to cleanup them or otherwise these
     will be leaked, let's use undocumented cleanup sequence - type UB */

  if(res)
    for(i = 0; i < NUM_HANDLES; i++)
      curl_easy_cleanup(curl[i]);

  curl_multi_cleanup(m);
  curl_global_cleanup();

#elif defined(LIB532)

  /* test 532 */
  /* undocumented cleanup sequence - type UB */

  for(i = 0; i < NUM_HANDLES; i++)
    curl_easy_cleanup(curl[i]);
  curl_multi_cleanup(m);
  curl_global_cleanup();

#endif

  return res;
}
