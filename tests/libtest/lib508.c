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

static char testdata[] = "this is what we post to the silly web server\n";

struct WriteThis
{
  char *readptr;
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;

  if (size * nmemb < 1)
    return 0;

  if (pooh->sizeleft)
  {
    *ptr = pooh->readptr[0]; /* copy one single byte */
    pooh->readptr++;         /* advance pointer */
    pooh->sizeleft--;        /* less data left */
    return 1;                /* we return 1 byte at a time! */
  }

  return 0; /* no more data left to deliver */
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  struct WriteThis pooh;

  pooh.readptr = testdata;
  pooh.sizeleft = strlen(testdata);

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
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)pooh.sizeleft);

  /* we want to use our own read function */
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

  /* pointer to pass to our read function */
  test_setopt(fetch, FETCHOPT_READDATA, &pooh);

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
