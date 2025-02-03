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
  FETCHcode res = FETCHE_OK;
  FETCHSH *share;
  FETCH *fetch;

  fetch_global_init(FETCH_GLOBAL_ALL);

  share = fetch_share_init();
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);

  fetch = fetch_easy_init();
  test_setopt(fetch, FETCHOPT_SHARE, share);

  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_PROXY, URL);
  test_setopt(fetch, FETCHOPT_URL, "http://localhost/");

  test_setopt(fetch, FETCHOPT_COOKIEFILE, "");

  /* Set a cookie without Max-age or Expires */
  test_setopt(fetch, FETCHOPT_COOKIELIST, "Set-Cookie: c1=v1; domain=localhost");

  res = fetch_easy_perform(fetch);
  if (res)
  {
    fprintf(stderr, "fetch_easy_perform() failed: %s\n",
            fetch_easy_strerror(res));
  }

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_share_cleanup(share);
  fetch_global_cleanup();

  return res;
}
