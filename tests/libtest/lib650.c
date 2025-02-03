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

static char testdata[] =
    "this is what we post to the silly web server";

static const char testname[] = "fieldname";

/* This test attempts to use all form API features that are not
 * used elsewhere.
 */

/* fetch_formget callback to count characters. */
static size_t count_chars(void *userp, const char *buf, size_t len)
{
  size_t *pcounter = (size_t *)userp;

  (void)buf;
  *pcounter += len;
  return len;
}

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = TEST_ERR_MAJOR_BAD;
  FETCHFORMcode formrc;
  struct fetch_slist *headers, *headers2 = NULL;
  struct fetch_httppost *formpost = NULL;
  struct fetch_httppost *lastptr = NULL;
  struct fetch_forms formarray[3];
  size_t formlength = 0;
  char flbuf[32];
  long contentlength = 0;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* Check proper name and data copying, as well as headers. */
  headers = fetch_slist_append(NULL, "X-customheader-1: Header 1 data");
  if (!headers)
  {
    goto test_cleanup;
  }
  headers2 = fetch_slist_append(headers, "X-customheader-2: Header 2 data");
  if (!headers2)
  {
    goto test_cleanup;
  }
  headers = headers2;
  headers2 = fetch_slist_append(headers, "Content-Type: text/plain");
  if (!headers2)
  {
    goto test_cleanup;
  }
  headers = headers2;
  FETCH_IGNORE_DEPRECATION(
      formrc = fetch_formadd(&formpost, &lastptr,
                             FETCHFORM_COPYNAME, &testname,
                             FETCHFORM_COPYCONTENTS, &testdata,
                             FETCHFORM_CONTENTHEADER, headers,
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(1) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  contentlength = (long)(strlen(testdata) - 1);

  FETCH_IGNORE_DEPRECATION(
      /* Use a form array for the non-copy test. */
      formarray[0].option = FETCHFORM_PTRCONTENTS;
      formarray[0].value = testdata;
      formarray[1].option = FETCHFORM_CONTENTSLENGTH;
      formarray[1].value = (char *)(size_t)contentlength;
      formarray[2].option = FETCHFORM_END;
      formarray[2].value = NULL;
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_PTRNAME, testname,
                             FETCHFORM_NAMELENGTH, strlen(testname) - 1,
                             FETCHFORM_ARRAY, formarray,
                             FETCHFORM_FILENAME, "remotefile.txt",
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(2) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  /* Now change in-memory data to affect FETCHOPT_PTRCONTENTS value.
     Copied values (first field) must not be affected.
     FETCHOPT_PTRNAME actually copies the name thus we do not test this here. */
  testdata[0]++;

  FETCH_IGNORE_DEPRECATION(
      /* Check multi-files and content type propagation. */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "multifile",
                             FETCHFORM_FILE, libtest_arg2, /* Set in first.c. */
                             FETCHFORM_FILE, libtest_arg2,
                             FETCHFORM_CONTENTTYPE, "text/whatever",
                             FETCHFORM_FILE, libtest_arg2,
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(3) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  FETCH_IGNORE_DEPRECATION(
      /* Check data from file content. */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "filecontents",
                             FETCHFORM_FILECONTENT, libtest_arg2,
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(4) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  FETCH_IGNORE_DEPRECATION(
      /* Measure the current form length.
       * This is done before including stdin data because we want to reuse it
       * and stdin cannot be rewound.
       */
      fetch_formget(formpost, (void *)&formlength, count_chars);)

  /* Include length in data for external check. */
  fetch_msnprintf(flbuf, sizeof(flbuf), "%lu", (unsigned long)formlength);
  FETCH_IGNORE_DEPRECATION(
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "formlength",
                             FETCHFORM_COPYCONTENTS, &flbuf,
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(5) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  FETCH_IGNORE_DEPRECATION(
      /* Check stdin (may be problematic on some platforms). */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "standardinput",
                             FETCHFORM_FILE, "-",
                             FETCHFORM_END);)
  if (formrc)
  {
    printf("fetch_formadd(6) = %d\n", (int)formrc);
    goto test_cleanup;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  FETCH_IGNORE_DEPRECATION(
      /* send a multi-part formpost */
      test_setopt(fetch, FETCHOPT_HTTPPOST, formpost);)

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  test_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
  test_setopt(fetch, FETCHOPT_POSTREDIR, (long)FETCH_REDIR_POST_301);

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
  fetch_slist_free_all(headers);

  fetch_global_cleanup();

  return res;
}
