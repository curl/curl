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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

/*
 * Get a single URL without select().
 */

FETCHcode test(char *URL)
{
  FETCH *handle = NULL;
  FETCHcode res = FETCHE_OK;
  FETCHU *urlp = NULL;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(handle);

  urlp = fetch_url();

  if (!urlp)
  {
    fprintf(stderr, "problem init URL api.");
    goto test_cleanup;
  }

  /* this doesn't set the PATH part */
  if (fetch_url_set(urlp, FETCHUPART_HOST, "www.example.com", 0) ||
      fetch_url_set(urlp, FETCHUPART_SCHEME, "http", 0) ||
      fetch_url_set(urlp, FETCHUPART_PORT, "80", 0))
  {
    fprintf(stderr, "problem setting FETCHUPART");
    goto test_cleanup;
  }

  easy_setopt(handle, FETCHOPT_FETCHU, urlp);
  easy_setopt(handle, FETCHOPT_VERBOSE, 1L);
  easy_setopt(handle, FETCHOPT_PROXY, URL);

  res = fetch_easy_perform(handle);

  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

test_cleanup:

  fetch_url_cleanup(urlp);
  fetch_easy_cleanup(handle);
  fetch_global_cleanup();

  return res;
}
