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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  char *url_after;
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  char error_buffer[FETCH_ERROR_SIZE] = "";

  fetch_global_init(FETCH_GLOBAL_DEFAULT);
  fetch = fetch_easy_init();
  fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
  fetch_easy_setopt(fetch, FETCHOPT_ERRORBUFFER, error_buffer);
  fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  res = fetch_easy_perform(fetch);
  if (!res)
    fprintf(stderr, "failure expected, "
                    "fetch_easy_perform returned %ld: <%s>, <%s>\n",
            (long)res, fetch_easy_strerror(res), error_buffer);

  /* print the used url */
  if (!fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_URL, &url_after))
    printf("Effective URL: %s\n", url_after);

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
