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

static char testbuf[17000]; /* more than 16K */

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  FETCHFORMcode formrc;
  struct fetch_httppost *formpost = NULL;
  struct fetch_httppost *lastptr = NULL;

  /* create a buffer with AAAA...BBBBB...CCCC...etc */
  int i;
  int size = (int)sizeof(testbuf) / 1000;

  for (i = 0; i < size; i++)
    memset(&testbuf[i * 1000], 65 + i, 1000);

  testbuf[sizeof(testbuf) - 1] = 0; /* null-terminate */

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  FETCH_IGNORE_DEPRECATION(
      /* Check proper name and data copying. */
      formrc = fetch_formadd(&formpost, &lastptr,
                             FETCHFORM_COPYNAME, "hello",
                             FETCHFORM_COPYCONTENTS, testbuf,
                             FETCHFORM_END);)
  if (formrc)
    printf("fetch_formadd(1) = %d\n", (int)formrc);

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    FETCH_IGNORE_DEPRECATION(
        fetch_formfree(formpost);)
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  FETCH_IGNORE_DEPRECATION(
      /* send a multi-part formpost */
      test_setopt(fetch, FETCHOPT_HTTPPOST, formpost);)

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);

  FETCH_IGNORE_DEPRECATION(
      /* now cleanup the formpost chain */
      fetch_formfree(formpost);)

  fetch_global_cleanup();

  return res;
}
