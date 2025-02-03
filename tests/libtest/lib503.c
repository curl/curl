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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

/*
 * Source code in here hugely as reported in bug report 651460 by
 * Christopher R. Palmer.
 *
 * Use multi interface to get HTTPS document over proxy, and provide
 * auth info.
 */

FETCHcode test(char *URL)
{
  FETCH *c = NULL;
  FETCHM *m = NULL;
  FETCHcode res = FETCHE_OK;
  int running;

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  easy_init(c);

  easy_setopt(c, FETCHOPT_PROXY, libtest_arg2); /* set in first.c */
  easy_setopt(c, FETCHOPT_URL, URL);
  easy_setopt(c, FETCHOPT_USERPWD, "test:ing");
  easy_setopt(c, FETCHOPT_PROXYUSERNAME, "test%20");
  easy_setopt(c, FETCHOPT_PROXYPASSWORD, "ing%41");
  easy_setopt(c, FETCHOPT_HTTPPROXYTUNNEL, 1L);
  easy_setopt(c, FETCHOPT_HEADER, 1L);
  easy_setopt(c, FETCHOPT_VERBOSE, 1L);

  multi_init(m);

  multi_add_handle(m, c);

  for (;;)
  {
    struct timeval interval;
    fd_set rd, wr, exc;
    int maxfd = -99;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    multi_perform(m, &running);

    abort_on_test_timeout();

    if (!running)
      break; /* done */

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    multi_fdset(m, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PA */

  fetch_multi_remove_handle(m, c);
  fetch_multi_cleanup(m);
  fetch_easy_cleanup(c);
  fetch_global_cleanup();

  return res;
}
