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

/* The size of data should be kept below MAX_INITIAL_POST_SIZE! */
static char testdata[] = "this is a short string.\n";

static size_t data_size = sizeof(testdata) / sizeof(char);

static int progress_callback(void *clientp, double dltotal, double dlnow,
                             double ultotal, double ulnow)
{
  FILE *moo = fopen(libtest_arg2, "wb");

  (void)clientp; /* UNUSED */
  (void)dltotal; /* UNUSED */
  (void)dlnow;   /* UNUSED */

  if (moo)
  {
    if ((size_t)ultotal == data_size && (size_t)ulnow == data_size)
      fprintf(moo, "PASSED, UL data matched data size\n");
    else
      fprintf(moo, "Progress callback called with UL %f out of %f\n",
              ulnow, ultotal);
    fclose(moo);
  }
  return 0;
}

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

  /* Now specify we want to POST data */
  test_setopt(fetch, FETCHOPT_POST, 1L);

  /* Set the expected POST size */
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)data_size);
  test_setopt(fetch, FETCHOPT_POSTFIELDS, testdata);

  /* we want to use our own progress function */
  FETCH_IGNORE_DEPRECATION(
      test_setopt(fetch, FETCHOPT_NOPROGRESS, 0L);
      test_setopt(fetch, FETCHOPT_PROGRESSFUNCTION, progress_callback);)

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
