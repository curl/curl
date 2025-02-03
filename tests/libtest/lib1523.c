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

/* test case and code based on https://github.com/fetch/fetch/issues/3927 */

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static int dload_progress_cb(void *a, fetch_off_t b, fetch_off_t c,
                             fetch_off_t d, fetch_off_t e)
{
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}

static size_t write_cb(char *d, size_t n, size_t l, void *p)
{
  /* take care of the data here, ignored in this example */
  (void)d;
  (void)p;
  return n * l;
}

static FETCHcode run(FETCH *hnd, long limit, long time)
{
  fetch_easy_setopt(hnd, FETCHOPT_LOW_SPEED_LIMIT, limit);
  fetch_easy_setopt(hnd, FETCHOPT_LOW_SPEED_TIME, time);
  return fetch_easy_perform(hnd);
}

FETCHcode test(char *URL)
{
  FETCHcode ret;
  FETCH *hnd;
  char buffer[FETCH_ERROR_SIZE];
  fetch_global_init(FETCH_GLOBAL_ALL);
  hnd = fetch_easy_init();
  fetch_easy_setopt(hnd, FETCHOPT_URL, URL);
  fetch_easy_setopt(hnd, FETCHOPT_WRITEFUNCTION, write_cb);
  fetch_easy_setopt(hnd, FETCHOPT_ERRORBUFFER, buffer);
  fetch_easy_setopt(hnd, FETCHOPT_NOPROGRESS, 0L);
  fetch_easy_setopt(hnd, FETCHOPT_XFERINFOFUNCTION, dload_progress_cb);

  ret = run(hnd, 1, 2);
  if (ret)
    fprintf(stderr, "error %d: %s\n", ret, buffer);

  ret = run(hnd, 12000, 1);
  if (ret != FETCHE_OPERATION_TIMEDOUT)
    fprintf(stderr, "error %d: %s\n", ret, buffer);
  else
    ret = FETCHE_OK;

  fetch_easy_cleanup(hnd);
  fetch_global_cleanup();

  return ret;
}
