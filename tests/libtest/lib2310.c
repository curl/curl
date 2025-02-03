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
#include "memdebug.h"

#ifndef FETCH_DISABLE_WEBSOCKETS

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  (void)b;
  (void)size;
  (void)nitems;
  (void)p;
  return 0;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);

    /* use the callback style */
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "webbie-sox/3");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, fetch);
    res = fetch_easy_perform(fetch);
    printf("Returned %d, should be %d.\n", res, FETCHE_RECV_ERROR);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return FETCHE_OK;
}

#else
NO_SUPPORT_BUILT_IN
#endif
