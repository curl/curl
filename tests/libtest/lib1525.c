/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Vijay Panghal, <vpanghal@maginatics.com>, et al.
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

/*
 * This unit test PUT http data over proxy. Proxy header will be different
 * from server http header
 */

#include "test.h"

#include "memdebug.h"

static char testdata[] = "Hello Cloud!\n";

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t amount = nmemb * size; /* Total bytes fetch wants */
  if (amount < strlen(testdata))
  {
    return strlen(testdata);
  }
  (void)stream;
  memcpy(ptr, testdata, strlen(testdata));
  return strlen(testdata);
}

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_FAILED_INIT;
  /* http and proxy header list */
  struct fetch_slist *hhl = NULL;

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

  if (!hhl)
  {
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_PROXY, libtest_arg2);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, hhl);
  test_setopt(fetch, FETCHOPT_PROXYHEADER, hhl);
  test_setopt(fetch, FETCHOPT_HEADEROPT, FETCHHEADER_UNIFIED);
  test_setopt(fetch, FETCHOPT_POST, 0L);
  test_setopt(fetch, FETCHOPT_UPLOAD, 1L);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_PROXYTYPE, FETCHPROXY_HTTP);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_WRITEFUNCTION, fwrite);
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
  test_setopt(fetch, FETCHOPT_HTTPPROXYTUNNEL, 1L);
  test_setopt(fetch, FETCHOPT_INFILESIZE, (long)strlen(testdata));

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);

  fetch_slist_free_all(hhl);

  fetch_global_cleanup();

  return res;
}
