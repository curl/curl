/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

#define NUM_HANDLES 4

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch[NUM_HANDLES] = {0};
  int running;
  FETCHM *m = NULL;
  int i;
  char target_url[256];
  char dnsentry[256];
  struct fetch_slist *slist = NULL;
  char *port = libtest_arg3;
  char *address = libtest_arg2;

  (void)URL;

  msnprintf(dnsentry, sizeof(dnsentry), "localhost:%s:%s",
            port, address);
  printf("%s\n", dnsentry);
  slist = fetch_slist_append(slist, dnsentry);
  if (!slist)
  {
    fprintf(stderr, "fetch_slist_append() failed\n");
    goto test_cleanup;
  }

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  multi_init(m);

  multi_setopt(m, FETCHMOPT_MAXCONNECTS, 1L);

  /* get NUM_HANDLES easy handles */
  for (i = 0; i < NUM_HANDLES; i++)
  {
    /* get an easy handle */
    easy_init(fetch[i]);
    /* specify target */
    msnprintf(target_url, sizeof(target_url),
              "https://localhost:%s/path/2404%04i",
              port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(fetch[i], FETCHOPT_URL, target_url);
    /* go http2 */
    easy_setopt(fetch[i], FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_2_0);
    /* no peer verify */
    easy_setopt(fetch[i], FETCHOPT_SSL_VERIFYPEER, 0L);
    easy_setopt(fetch[i], FETCHOPT_SSL_VERIFYHOST, 0L);
    /* wait for first connection established to see if we can share it */
    easy_setopt(fetch[i], FETCHOPT_PIPEWAIT, 1L);
    /* go verbose */
    easy_setopt(fetch[i], FETCHOPT_VERBOSE, 1L);
    /* include headers */
    easy_setopt(fetch[i], FETCHOPT_HEADER, 1L);

    easy_setopt(fetch[i], FETCHOPT_RESOLVE, slist);

    easy_setopt(fetch[i], FETCHOPT_STREAM_WEIGHT, (long)128 + i);
  }

  fprintf(stderr, "Start at URL 0\n");

  for (i = 0; i < NUM_HANDLES; i++)
  {
    /* add handle to multi */
    multi_add_handle(m, fetch[i]);

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
    wait_ms(1); /* to ensure different end times */
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  for (i = 0; i < NUM_HANDLES; i++)
  {
    fetch_multi_remove_handle(m, fetch[i]);
    fetch_easy_cleanup(fetch[i]);
  }

  fetch_slist_free_all(slist);

  fetch_multi_cleanup(m);
  fetch_global_cleanup();

  return res;
}
