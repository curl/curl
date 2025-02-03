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

#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_FAILED_INIT;
  /* http header list */
  struct fetch_slist *hhl = NULL;
  struct fetch_slist *phl = NULL;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  hhl = fetch_slist_append(hhl, "User-Agent: Http Agent");
  phl = fetch_slist_append(phl, "Proxy-User-Agent: Http Agent2");

  if (!hhl)
  {
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_PROXY, libtest_arg2);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, hhl);
  test_setopt(fetch, FETCHOPT_PROXYHEADER, phl);
  test_setopt(fetch, FETCHOPT_HEADEROPT, FETCHHEADER_SEPARATE);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_PROXYTYPE, FETCHPROXY_HTTP);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_slist_free_all(hhl);
  fetch_slist_free_all(phl);
  fetch_global_cleanup();

  return res;
}
