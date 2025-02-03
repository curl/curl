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

#include "memdebug.h"

FETCHcode test(char *URL)
{
  long unmet;
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_HEADER, 1L);
  easy_setopt(fetch, FETCHOPT_TIMECONDITION, (long)FETCH_TIMECOND_IFMODSINCE);

  /* TIMEVALUE in the future */
  easy_setopt(fetch, FETCHOPT_TIMEVALUE, 1566210680L);

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  fetch_easy_getinfo(fetch, FETCHINFO_CONDITION_UNMET, &unmet);
  if(unmet != 1L) {
    res = TEST_ERR_FAILURE; /* not correct */
    goto test_cleanup;
  }

  /* TIMEVALUE in the past */
  easy_setopt(fetch, FETCHOPT_TIMEVALUE, 1L);

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  fetch_easy_getinfo(fetch, FETCHINFO_CONDITION_UNMET, &unmet);
  if(unmet) {
    res = TEST_ERR_FAILURE; /* not correct */
    goto test_cleanup;
  }

  res = TEST_ERR_SUCCESS; /* this is where we should be */

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
