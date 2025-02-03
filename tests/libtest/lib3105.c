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

FETCHcode test(char *URL)
{
  FETCH *fetchs = NULL;
  FETCHM *multi = NULL;
  FETCHcode i = FETCHE_OK;
  FETCHcode res = FETCHE_OK;
  FETCHMcode mc;

  global_init(FETCH_GLOBAL_ALL);

  multi_init(multi);

  easy_init(fetchs);

  easy_setopt(fetchs, FETCHOPT_URL, URL);

  multi_add_handle(multi, fetchs);

  mc = fetch_multi_remove_handle(multi, fetchs);
  mc += fetch_multi_remove_handle(multi, fetchs);

  if(mc) {
    fprintf(stderr, "%d was unexpected\n", (int)mc);
    i = FETCHE_FAILED_INIT;
  }

test_cleanup:
  fetch_multi_cleanup(multi);
  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();

  if(res)
    i = res;

  return i; /* return the final return code */
}
