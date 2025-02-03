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

#include <fetch/multi.h>

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;
  FETCHU *u = NULL;

  global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();
  if (fetch)
  {
    u = fetch_url();
    if (u)
    {
      fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
      fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
      fetch_url_set(u, FETCHUPART_URL, URL, 0);
      fetch_easy_setopt(fetch, FETCHOPT_FETCHU, u);
      res = fetch_easy_perform(fetch);
      if (res)
        goto test_cleanup;

      fprintf(stderr, "****************************** Do it again\n");
      res = fetch_easy_perform(fetch);
    }
  }

test_cleanup:
  fetch_url_cleanup(u);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
