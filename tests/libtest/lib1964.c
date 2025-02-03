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
  FETCHcode res = FETCHE_OK;
  struct fetch_slist *connect_to = NULL;
  struct fetch_slist *list = NULL, *tmp;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  easy_setopt(fetch, FETCHOPT_AWS_SIGV4, "xxx");
  easy_setopt(fetch, FETCHOPT_URL, URL);
  if(libtest_arg2) {
    connect_to = fetch_slist_append(connect_to, libtest_arg2);
    if(!connect_to) {
      res = FETCHE_FAILED_INIT;
      goto test_cleanup;
    }
  }
  easy_setopt(fetch, FETCHOPT_CONNECT_TO, connect_to);
  list = fetch_slist_append(list, "Content-Type: application/json");
  tmp = fetch_slist_append(list, "X-Xxx-Date: 19700101T000000Z");
  if(!list || !tmp) {
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }
  list = tmp;
  easy_setopt(fetch, FETCHOPT_HTTPHEADER, list);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_slist_free_all(connect_to);
  fetch_slist_free_all(list);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
