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

#define URL2 libtest_arg2

FETCHcode test(char *URL)
{
  /* first a fine GET response, then a bad one */
  FETCH *cl;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(cl);
  easy_setopt(cl, FETCHOPT_URL, URL);
  easy_setopt(cl, FETCHOPT_VERBOSE, 1L);
  res = fetch_easy_perform(cl);
  if (res)
    goto test_cleanup;

  /* reuse handle, do a second transfer */
  easy_setopt(cl, FETCHOPT_URL, URL2);
  res = fetch_easy_perform(cl);

test_cleanup:
  fetch_easy_cleanup(cl);
  fetch_global_cleanup();
  return res;
}
