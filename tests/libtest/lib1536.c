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

/* Test FETCHINFO_SCHEME */

FETCHcode test(char *URL)
{
  FETCH *fetch, *dupe = NULL;
  char *scheme;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  /* Test that scheme is properly initialized on fetch_easy_init.
   */

  res = fetch_easy_getinfo(fetch, FETCHINFO_SCHEME, &scheme);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (scheme)
  {
    fprintf(stderr, "%s:%d scheme init failed; expected NULL\n",
            __FILE__, __LINE__);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  easy_setopt(fetch, FETCHOPT_URL, URL);

  res = fetch_easy_perform(fetch);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  /* Test that a scheme is properly set after receiving an HTTP resource.
   */

  res = fetch_easy_getinfo(fetch, FETCHINFO_SCHEME, &scheme);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (!scheme || memcmp(scheme, "http", 5) != 0)
  {
    fprintf(stderr, "%s:%d scheme of http resource is incorrect; "
                    "expected 'http' but is %s\n",
            __FILE__, __LINE__,
            (scheme == NULL ? "NULL" : "invalid"));
    res = FETCHE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

  /* Test that a scheme is properly initialized on fetch_easy_duphandle.
   */

  dupe = fetch_easy_duphandle(fetch);
  if (!dupe)
  {
    fprintf(stderr, "%s:%d fetch_easy_duphandle() failed\n",
            __FILE__, __LINE__);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  res = fetch_easy_getinfo(dupe, FETCHINFO_SCHEME, &scheme);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (scheme)
  {
    fprintf(stderr, "%s:%d scheme init failed; expected NULL\n",
            __FILE__, __LINE__);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  /* Test that a scheme is properly initialized on fetch_easy_reset.
   */

  fetch_easy_reset(fetch);

  res = fetch_easy_getinfo(fetch, FETCHINFO_SCHEME, &scheme);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (scheme)
  {
    fprintf(stderr, "%s:%d scheme init failed; expected NULL\n",
            __FILE__, __LINE__);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_easy_cleanup(dupe);
  fetch_global_cleanup();
  return res;
}
