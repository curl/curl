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

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch = NULL;
  long protocol = 0;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);
  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform() returned %d (%s)\n",
            res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  FETCH_IGNORE_DEPRECATION(
    res = fetch_easy_getinfo(fetch, FETCHINFO_PROTOCOL, &protocol);
  )
  if(res) {
    fprintf(stderr, "fetch_easy_getinfo() returned %d (%s)\n",
            res, fetch_easy_strerror(res));
    goto test_cleanup;
  }

  printf("Protocol: %lx\n", protocol);

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return FETCHE_OK;

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res; /* return the final return code */
}
