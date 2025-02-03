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
/*
 * Test case converted from bug report #1318 by Petr Novak.
 *
 * Before the fix, this test program returned 52 (FETCHE_GOT_NOTHING) instead
 * of 42 (FETCHE_ABORTED_BY_CALLBACK).
 */

#include "test.h"

#include "memdebug.h"

static int progressKiller(void *arg,
                          double dltotal,
                          double dlnow,
                          double ultotal,
                          double ulnow)
{
  (void)arg;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  printf("PROGRESSFUNCTION called\n");
  return 1;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_TIMEOUT, (long)7);
  easy_setopt(fetch, FETCHOPT_NOSIGNAL, (long)1);
  FETCH_IGNORE_DEPRECATION(
    easy_setopt(fetch, FETCHOPT_PROGRESSFUNCTION, progressKiller);
    easy_setopt(fetch, FETCHOPT_PROGRESSDATA, NULL);
  )
  easy_setopt(fetch, FETCHOPT_NOPROGRESS, (long)0);

  res = fetch_easy_perform(fetch);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
