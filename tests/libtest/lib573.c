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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testtrace.h"
#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

/*
 * Get a single URL without select().
 */

FETCHcode test(char *URL)
{
  FETCH *c = NULL;
  FETCHM *m = NULL;
  FETCHcode res = FETCHE_OK;
  int running = 1;
  double connect_time = 0.0;
  double dbl_epsilon;

  dbl_epsilon = 1.0;
  do {
    dbl_epsilon /= 2.0;
  } while((double)(1.0 + (dbl_epsilon/2.0)) > (double)1.0);

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  easy_init(c);

  easy_setopt(c, FETCHOPT_HEADER, 1L);
  easy_setopt(c, FETCHOPT_URL, URL);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  easy_setopt(c, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(c, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(c, FETCHOPT_VERBOSE, 1L);

  multi_init(m);

  multi_add_handle(m, c);

  while(running) {
    struct timeval timeout;
    fd_set fdread, fdwrite, fdexcep;
    int maxfd = -99;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000L; /* 100 ms */

    multi_perform(m, &running);

    abort_on_test_timeout();

    if(!running)
      break; /* done */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    multi_fdset(m, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    abort_on_test_timeout();
  }

  fetch_easy_getinfo(c, FETCHINFO_CONNECT_TIME, &connect_time);
  if(connect_time < dbl_epsilon) {
    fprintf(stderr, "connect time %e is < epsilon %e\n",
            connect_time, dbl_epsilon);
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence - type PA */

  fetch_multi_remove_handle(m, c);
  fetch_multi_cleanup(m);
  fetch_easy_cleanup(c);
  fetch_global_cleanup();

  return res;
}
