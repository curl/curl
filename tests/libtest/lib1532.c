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

/* Test FETCHINFO_RESPONSE_CODE */

FETCHcode test(char *URL)
{
  FETCH *fetch;
  long httpcode;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);

  res = fetch_easy_perform(fetch);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  res = fetch_easy_getinfo(fetch, FETCHINFO_RESPONSE_CODE, &httpcode);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (httpcode != 200)
  {
    fprintf(stderr, "%s:%d unexpected response code %ld\n",
            __FILE__, __LINE__, httpcode);
    res = FETCHE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

  /* Test for a regression of github bug 1017 (response code does not reset) */
  fetch_easy_reset(fetch);

  res = fetch_easy_getinfo(fetch, FETCHINFO_RESPONSE_CODE, &httpcode);
  if (res)
  {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }
  if (httpcode)
  {
    fprintf(stderr, "%s:%d fetch_easy_reset failed to zero the response code\n"
                    "possible regression of github bug 1017\n",
            __FILE__, __LINE__);
    res = FETCHE_HTTP_RETURNED_ERROR;
    goto test_cleanup;
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
