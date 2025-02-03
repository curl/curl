/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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
  FETCHcode ret = FETCHE_OK;
  FETCH *hnd;
  start_test_timing();

  fetch_global_init(FETCH_GLOBAL_ALL);

  hnd = fetch_easy_init();
  if(hnd) {
    fetch_easy_setopt(hnd, FETCHOPT_URL, URL);
    fetch_easy_setopt(hnd, FETCHOPT_NOPROGRESS, 1L);
    fetch_easy_setopt(hnd, FETCHOPT_FOLLOWLOCATION, 1L);
    fetch_easy_setopt(hnd, FETCHOPT_USERPWD, "user\nname:pass\nword");
    ret = fetch_easy_perform(hnd);
    fetch_easy_cleanup(hnd);
  }
  fetch_global_cleanup();
  return ret;
}
