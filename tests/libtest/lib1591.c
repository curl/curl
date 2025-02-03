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

/*
 * This unit test PUT http data over proxy. Proxy header will be different
 * from server http header
 */

#include "test.h"
#include <stdio.h>
#include "memdebug.h"

static char testdata[] = "Hello Cloud!\r\n";
static size_t consumed = 0;

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t amount = nmemb * size; /* Total bytes fetch wants */

  if (consumed == strlen(testdata))
  {
    return 0;
  }

  if (amount > strlen(testdata) - consumed)
  {
    amount = strlen(testdata);
  }

  consumed += amount;
  (void)stream;
  memcpy(ptr, testdata, amount);
  return amount;
}

/*
 * carefully not leak memory on OOM
 */
static int trailers_callback(struct fetch_slist **list, void *userdata)
{
  struct fetch_slist *nlist = NULL;
  struct fetch_slist *nlist2 = NULL;
  (void)userdata;
  nlist = fetch_slist_append(*list, "my-super-awesome-trailer: trail1");
  if (nlist)
    nlist2 = fetch_slist_append(nlist, "my-other-awesome-trailer: trail2");
  if (nlist2)
  {
    *list = nlist2;
    return FETCH_TRAILERFUNC_OK;
  }
  else
  {
    fetch_slist_free_all(nlist);
    return FETCH_TRAILERFUNC_ABORT;
  }
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

  hhl = fetch_slist_append(hhl, "Trailer: my-super-awesome-trailer,"
                                " my-other-awesome-trailer");
  if (!hhl)
  {
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, hhl);
  test_setopt(fetch, FETCHOPT_UPLOAD, 1L);
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
  test_setopt(fetch, FETCHOPT_TRAILERFUNCTION, trailers_callback);
  test_setopt(fetch, FETCHOPT_TRAILERDATA, NULL);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);

  fetch_slist_free_all(hhl);

  fetch_global_cleanup();

  return res;
}
