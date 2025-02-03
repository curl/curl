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
  struct fetch_slist *list = NULL;
  struct fetch_slist *connect_to = NULL;

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
  test_setopt(fetch, FETCHOPT_AWS_SIGV4, "xxx");
  test_setopt(fetch, FETCHOPT_USERPWD, "xxx");
  test_setopt(fetch, FETCHOPT_HEADER, 0L);
  test_setopt(fetch, FETCHOPT_URL, URL);
  list = fetch_slist_append(list, "test3: 1234");
  if(!list)
    goto test_cleanup;
  if(libtest_arg2) {
    connect_to = fetch_slist_append(connect_to, libtest_arg2);
  }
  test_setopt(fetch, FETCHOPT_CONNECT_TO, connect_to);
  fetch_slist_append(list, "Content-Type: application/json");

  /* 'name;' user headers with no value are used to send an empty header in the
     format 'name:' (note the semi-colon becomes a colon). this entry should
     show in SignedHeaders without an additional semi-colon, as any other
     header would. eg 'foo;test2;test3' and not 'foo;test2;;test3'. */
  fetch_slist_append(list, "test2;");

  /* 'name:' user headers with no value are used to signal an internal header
     of that name should be removed and are not sent as a header. this entry
     should not show in SignedHeaders. */
  fetch_slist_append(list, "test1:");

  /* 'name' user headers with no separator or value are invalid and ignored.
     this entry should not show in SignedHeaders. */
  fetch_slist_append(list, "test0");

  fetch_slist_append(list, "test_space: t\ts  m\t   end    ");
  fetch_slist_append(list, "tesMixCase: MixCase");
  test_setopt(fetch, FETCHOPT_HTTPHEADER, list);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_slist_free_all(connect_to);
  fetch_slist_free_all(list);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
