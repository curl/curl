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

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *hnd = NULL;
  FETCH *second = NULL;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(hnd);
  easy_setopt(hnd, FETCHOPT_URL, URL);
  easy_setopt(hnd, FETCHOPT_HSTS, "first-hsts.txt");
  easy_setopt(hnd, FETCHOPT_HSTS, "second-hsts.txt");

  second = fetch_easy_duphandle(hnd);

  fetch_easy_cleanup(hnd);
  fetch_easy_cleanup(second);
  fetch_global_cleanup();
  return FETCHE_OK;

test_cleanup:
  fetch_easy_cleanup(hnd);
  fetch_easy_cleanup(second);
  fetch_global_cleanup();
  return res;
}
