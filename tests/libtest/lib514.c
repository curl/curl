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
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Based on a bug report by Niels van Tongeren on June 29, 2004:

  A weird situation occurs when request 1 is a POST request and the request
  2 is a HEAD request. For the POST request we set the FETCHOPT_POSTFIELDS,
  FETCHOPT_POSTFIELDSIZE and FETCHOPT_POST options. For the HEAD request we
  set the FETCHOPT_NOBODY option to '1'.

  */

  test_setopt(fetch, FETCHOPT_POSTFIELDS, "moo");
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, 3L);
  test_setopt(fetch, FETCHOPT_POST, 1L);

  /* this is where transfer 1 would take place, but skip that and change
     options right away instead */

  test_setopt(fetch, FETCHOPT_NOBODY, 1L);

  test_setopt(fetch, FETCHOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);  /* include header */

  /* Now, we should be making a fine HEAD request */

  /* Perform the request 2, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
