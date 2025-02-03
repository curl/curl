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

/* Test FETCHINFO_FILETIME */

FETCHcode test(char *URL)
{
  FETCH *fetch, *dupe = NULL;
  long filetime;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  /* Test that a filetime is properly initialized on fetch_easy_init.
   */

  res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME, &filetime);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (filetime != -1)
  {
    fprintf(stderr, "%s:%d filetime init failed; expected -1 but is %ld\n",
            __FILE__, __LINE__, filetime);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_FILETIME, 1L);

  res = fetch_easy_perform(fetch);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  /* Test that a filetime is properly set after receiving an HTTP resource.
   */

  res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME, &filetime);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (filetime != 30)
  {
    fprintf(stderr, "%s:%d filetime of http resource is incorrect; "
                    "expected 30 but is %ld\n",
            __FILE__, __LINE__, filetime);
    res = FETCHE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

  /* Test that a filetime is properly initialized on fetch_easy_duphandle.
   */

  dupe = fetch_easy_duphandle(fetch);
  if (!dupe)
  {
    fprintf(stderr, "%s:%d fetch_easy_duphandle() failed\n",
            __FILE__, __LINE__);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  res = fetch_easy_getinfo(dupe, FETCHINFO_FILETIME, &filetime);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (filetime != -1)
  {
    fprintf(stderr, "%s:%d filetime init failed; expected -1 but is %ld\n",
            __FILE__, __LINE__, filetime);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

  /* Test that a filetime is properly initialized on fetch_easy_reset.
   */

  fetch_easy_reset(fetch);

  res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME, &filetime);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (filetime != -1)
  {
    fprintf(stderr, "%s:%d filetime init failed; expected -1 but is %ld\n",
            __FILE__, __LINE__, filetime);
    res = FETCHE_FAILED_INIT;
    goto test_cleanup;
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_easy_cleanup(dupe);
  fetch_global_cleanup();
  return res;
}
