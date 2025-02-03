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

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "memdebug.h"

/*
 * From "KNOWN_BUGS" April 2009:

 59. If the FETCHOPT_PORT option is used on an FTP URL like
 "ftp://example.com/file;type=A" the ";type=A" is stripped off.

 */

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* get a fetch handle */
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* enable verbose */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* set port number */
  test_setopt(fetch, FETCHOPT_PORT, strtol(libtest_arg2, NULL, 10));

  /* specify target */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Now run off and do what you've been told! */
  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
