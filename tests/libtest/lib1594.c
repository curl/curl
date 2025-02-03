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

/* Testing Retry-After header parser */

#include "test.h"

#include "memdebug.h"

FETCHcode test(char *URL)
{
  struct fetch_slist *header = NULL;
  fetch_off_t retry;
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);

  res = fetch_easy_perform(fetch);
  if (res)
    goto test_cleanup;

  res = fetch_easy_getinfo(fetch, FETCHINFO_RETRY_AFTER, &retry);
  if (res)
    goto test_cleanup;

  printf("Retry-After %" FETCH_FORMAT_FETCH_OFF_T "\n", retry);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_slist_free_all(header);
  fetch_global_cleanup();

  return res;
}
