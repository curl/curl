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

#define TEST_HANG_TIMEOUT (60 * 1000)

static int new_fnmatch(void *ptr,
                       const char *pattern, const char *string)
{
  (void)ptr;
  fprintf(stderr, "lib574: match string '%s' against pattern '%s'\n",
          string, pattern);
  return FETCH_FNMATCHFUNC_MATCH;
}

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_WILDCARDMATCH, 1L);
  test_setopt(fetch, FETCHOPT_FNMATCH_FUNCTION, new_fnmatch);
  test_setopt(fetch, FETCHOPT_TIMEOUT_MS, (long) TEST_HANG_TIMEOUT);

  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform() failed %d\n", res);
    goto test_cleanup;
  }
  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform() failed %d\n", res);
    goto test_cleanup;
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
