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
  FETCH *handle2;
  FETCHcode res = FETCHE_OK;
  FETCHU *urlp = NULL;
  FETCHUcode uc = FETCHUE_OK;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(handle);

  urlp = fetch_url();

  if(!urlp) {
    fprintf(stderr, "problem init URL api.");
    goto test_cleanup;
  }

  uc = fetch_url_set(urlp, FETCHUPART_URL, URL, 0);
  if(uc) {
    fprintf(stderr, "problem setting FETCHUPART_URL: %s.",
            fetch_url_strerror(uc));
    goto test_cleanup;
  }

  /* demonstrate override behavior */


  easy_setopt(handle, FETCHOPT_FETCHU, urlp);
  easy_setopt(handle, FETCHOPT_VERBOSE, 1L);

  res = fetch_easy_perform(handle);

  if(res) {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
            __FILE__, __LINE__, res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  handle2 = fetch_easy_duphandle(handle);
  res = fetch_easy_perform(handle2);
  fetch_easy_cleanup(handle2);

test_cleanup:

  fetch_url_cleanup(urlp);
  fetch_easy_cleanup(handle);
  fetch_global_cleanup();

  return res;
}
