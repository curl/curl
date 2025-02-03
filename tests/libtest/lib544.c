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

static char teststring[] =
    {'T', 'h', 'i', 's', '\0', ' ', 'i', 's', ' ', 't', 'e', 's', 't', ' ',
     'b', 'i', 'n', 'a', 'r', 'y', ' ', 'd', 'a', 't', 'a', ' ',
     'w', 'i', 't', 'h', ' ', 'a', 'n', ' ',
     'e', 'm', 'b', 'e', 'd', 'd', 'e', 'd', ' ', 'N', 'U', 'L'};

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

#ifdef LIB545
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)sizeof(teststring));
#endif

  test_setopt(fetch, FETCHOPT_COPYPOSTFIELDS, teststring);

  test_setopt(fetch, FETCHOPT_VERBOSE, 1L); /* show verbose for debug */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);  /* include header */

  /* Update the original data to detect non-copy. */
  strcpy(teststring, "FAIL");

  {
    FETCH *handle2;
    handle2 = fetch_easy_duphandle(fetch);
    fetch_easy_cleanup(fetch);

    fetch = handle2;
  }

  /* Now, this is a POST request with binary 0 embedded in POST data. */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
