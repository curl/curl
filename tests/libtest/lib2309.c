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

#include <fetch/fetch.h>

static size_t cb_ignore(char *buffer, size_t size, size_t nmemb, void *userp)
{
  (void)buffer;
  (void)size;
  (void)nmemb;
  (void)userp;
  return FETCH_WRITEFUNC_ERROR;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCH *fetchdupe;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, cb_ignore);
    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, libtest_arg3);
    fetch_easy_setopt(fetch, FETCHOPT_NETRC, (long)FETCH_NETRC_REQUIRED);
    fetch_easy_setopt(fetch, FETCHOPT_NETRC_FILE, libtest_arg2);

    fetchdupe = fetch_easy_duphandle(fetch);
    if(fetchdupe) {
      res = fetch_easy_perform(fetchdupe);
      printf("Returned %d, should be %d.\n", res, FETCHE_WRITE_ERROR);
      fflush(stdout);
      fetch_easy_cleanup(fetchdupe);
    }
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return FETCHE_OK;
}
