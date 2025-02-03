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

static const char *const testpost[] = {
    "one",
    "two",
    "three",
    "and a final longer crap: four",
    NULL};

struct WriteThis
{
  int counter;
};

static bool started = FALSE;
static size_t last_ul = 0;
static size_t last_ul_total = 0;

static void progress_final_report(void)
{
  FILE *moo = fopen(libtest_arg2, "ab");
  fprintf(moo, "Progress: end UL %zu/%zu\n", last_ul, last_ul_total);
  started = FALSE;
  fclose(moo);
}

static int progress_callback(void *clientp, double dltotal, double dlnow,
                             double ultotal, double ulnow)
{
  (void)clientp; /* UNUSED */
  (void)dltotal; /* UNUSED */
  (void)dlnow;   /* UNUSED */

  if (started && ulnow <= 0.0 && last_ul)
  {
    progress_final_report();
  }

  last_ul = (size_t)ulnow;
  last_ul_total = (size_t)ultotal;
  if (!started)
  {
    FILE *moo = fopen(libtest_arg2, "ab");
    fprintf(moo, "Progress: start UL %zu/%zu\n", last_ul, last_ul_total);
    started = TRUE;
    fclose(moo);
  }

  return 0;
}

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  const char *data;

  if (size * nmemb < 1)
    return 0;

  data = testpost[pooh->counter];

  if (data)
  {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    pooh->counter++; /* advance pointer */
    return len;
  }
  return 0; /* no more data left to deliver */
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct fetch_slist *slist = NULL;
  struct WriteThis pooh;
  pooh.counter = 0;

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

  slist = fetch_slist_append(slist, "Transfer-Encoding: chunked");
  if (!slist)
  {
    fprintf(stderr, "fetch_slist_append() failed\n");
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Now specify we want to POST data */
  test_setopt(fetch, FETCHOPT_POST, 1L);

  /* we want to use our own read function */
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

  /* pointer to pass to our read function */
  test_setopt(fetch, FETCHOPT_READDATA, &pooh);

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  /* enforce chunked transfer by setting the header */
  test_setopt(fetch, FETCHOPT_HTTPHEADER, slist);

  test_setopt(fetch, FETCHOPT_HTTPAUTH, (long)FETCHAUTH_DIGEST);
  test_setopt(fetch, FETCHOPT_USERPWD, "foo:bar");

  /* we want to use our own progress function */
  test_setopt(fetch, FETCHOPT_NOPROGRESS, 0L);
  FETCH_IGNORE_DEPRECATION(
      test_setopt(fetch, FETCHOPT_PROGRESSFUNCTION, progress_callback);)

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

  progress_final_report();

test_cleanup:

  /* clean up the headers list */
  if (slist)
    fetch_slist_free_all(slist);

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
