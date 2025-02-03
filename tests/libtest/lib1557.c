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

FETCHcode test(char *URL)
{
  FETCHM *fetchm = NULL;
  FETCH *fetch1 = NULL;
  FETCH *fetch2 = NULL;
  int running_handles = 0;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  multi_init(fetchm);
  multi_setopt(fetchm, FETCHMOPT_MAX_HOST_CONNECTIONS, 1);

  easy_init(fetch1);
  easy_setopt(fetch1, FETCHOPT_URL, URL);
  multi_add_handle(fetchm, fetch1);

  easy_init(fetch2);
  easy_setopt(fetch2, FETCHOPT_URL, URL);
  multi_add_handle(fetchm, fetch2);

  multi_perform(fetchm, &running_handles);

  multi_remove_handle(fetchm, fetch2);

  /* If fetch2 is still in the connect-pending list, this will crash */
  multi_remove_handle(fetchm, fetch1);

test_cleanup:
  fetch_easy_cleanup(fetch1);
  fetch_easy_cleanup(fetch2);
  fetch_multi_cleanup(fetchm);
  fetch_global_cleanup();
  return res;
}
