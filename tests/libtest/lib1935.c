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
 * are also available at https://fetch.haxx.se/docs/copyright.html.
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
  FETCH *fetch;
  FETCHcode res = TEST_ERR_MAJOR_BAD;
  struct fetch_slist *connect_to = NULL;
  struct fetch_slist *list = NULL;

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

  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_AWS_SIGV4, "xxx:yyy:rrr");
  test_setopt(fetch, FETCHOPT_USERPWD, "xxx:yyy");
  test_setopt(fetch, FETCHOPT_HEADER, 0L);
  test_setopt(fetch, FETCHOPT_URL, URL);
  if(libtest_arg2) {
    connect_to = fetch_slist_append(connect_to, libtest_arg2);
  }
  test_setopt(fetch, FETCHOPT_CONNECT_TO, connect_to);
  list = fetch_slist_append(list, "Content-Type: application/json");
  test_setopt(fetch, FETCHOPT_HTTPHEADER, list);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_slist_free_all(connect_to);
  fetch_slist_free_all(list);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
