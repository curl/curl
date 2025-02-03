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

FETCHcode test(char *URL)
{
  FETCHcode ret;
  FETCH *hnd;
  fetch_global_init(FETCH_GLOBAL_ALL);

  hnd = fetch_easy_init();
  fetch_easy_setopt(hnd, FETCHOPT_URL, URL);
  fetch_easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
  fetch_easy_setopt(hnd, FETCHOPT_HEADER, 1L);
  fetch_easy_setopt(hnd, FETCHOPT_USERPWD, "testuser:testpass");
  fetch_easy_setopt(hnd, FETCHOPT_USERAGENT, "lib1568");
  fetch_easy_setopt(hnd, FETCHOPT_HTTPAUTH, (long)FETCHAUTH_DIGEST);
  fetch_easy_setopt(hnd, FETCHOPT_MAXREDIRS, 50L);
  fetch_easy_setopt(hnd, FETCHOPT_PORT, strtol(libtest_arg2, NULL, 10));

  ret = fetch_easy_perform(hnd);

  fetch_easy_cleanup(hnd);
  hnd = NULL;

  fetch_global_cleanup();
  return ret;
}
