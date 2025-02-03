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

static char testdata[] =
    "this is what we post to the silly web server\n";

struct WriteThis
{
  char *readptr;
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
#ifdef LIB587
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return FETCH_READFUNC_ABORT;
#else

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
#endif
}

static FETCHcode test_once(char *URL, bool oldstyle)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  FETCHFORMcode formrc;

  struct fetch_httppost *formpost = NULL;
  struct fetch_httppost *lastptr = NULL;
  struct WriteThis pooh;
  struct WriteThis pooh2;

  pooh.readptr = testdata;
  pooh.sizeleft = strlen(testdata);

  /* Fill in the file upload field */
  if (oldstyle)
  {
    FETCH_IGNORE_DEPRECATION(
        formrc = fetch_formadd(&formpost,
                               &lastptr,
                               FETCHFORM_COPYNAME, "sendfile",
                               FETCHFORM_STREAM, &pooh,
                               FETCHFORM_CONTENTSLENGTH, (long)pooh.sizeleft,
                               FETCHFORM_FILENAME, "postit2.c",
                               FETCHFORM_END);)
  }
  else
  {
    FETCH_IGNORE_DEPRECATION(
        /* new style */
        formrc = fetch_formadd(&formpost,
                               &lastptr,
                               FETCHFORM_COPYNAME, "sendfile alternative",
                               FETCHFORM_STREAM, &pooh,
                               FETCHFORM_CONTENTLEN, (fetch_off_t)pooh.sizeleft,
                               FETCHFORM_FILENAME, "file name 2",
                               FETCHFORM_END);)
  }

  if (formrc)
    printf("fetch_formadd(1) = %d\n", (int)formrc);

  /* Now add the same data with another name and make it not look like
     a file upload but still using the callback */

  pooh2.readptr = testdata;
  pooh2.sizeleft = strlen(testdata);

  FETCH_IGNORE_DEPRECATION(
      /* Fill in the file upload field */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "callbackdata",
                             FETCHFORM_STREAM, &pooh2,
                             FETCHFORM_CONTENTSLENGTH, (long)pooh2.sizeleft,
                             FETCHFORM_END);)
  if (formrc)
    printf("fetch_formadd(2) = %d\n", (int)formrc);

  FETCH_IGNORE_DEPRECATION(
      /* Fill in the filename field */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "filename",
                             FETCHFORM_COPYCONTENTS, "postit2.c",
                             FETCHFORM_END);)
  if (formrc)
    printf("fetch_formadd(3) = %d\n", (int)formrc);

  FETCH_IGNORE_DEPRECATION(
      /* Fill in a submit field too */
      formrc = fetch_formadd(&formpost,
                             &lastptr,
                             FETCHFORM_COPYNAME, "submit",
                             FETCHFORM_COPYCONTENTS, "send",
                             FETCHFORM_CONTENTTYPE, "text/plain",
                             FETCHFORM_END);)
  if (formrc)
    printf("fetch_formadd(4) = %d\n", (int)formrc);

  FETCH_IGNORE_DEPRECATION(
      formrc = fetch_formadd(&formpost, &lastptr,
                             FETCHFORM_COPYNAME, "somename",
                             FETCHFORM_BUFFER, "somefile.txt",
                             FETCHFORM_BUFFERPTR, "blah blah",
                             FETCHFORM_BUFFERLENGTH, (long)9,
                             FETCHFORM_END);)
  if (formrc)
    printf("fetch_formadd(5) = %d\n", (int)formrc);

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

  /* Now specify we want to POST data */
  test_setopt(fetch, FETCHOPT_POST, 1L);

  /* Set the expected POST size */
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)pooh.sizeleft);

  /* we want to use our own read function */
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

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

  FETCH_IGNORE_DEPRECATION(
      /* always cleanup */
      fetch_easy_cleanup(fetch);)

  FETCH_IGNORE_DEPRECATION(
      /* now cleanup the formpost chain */
      fetch_formfree(formpost);)

  return res;
}

FETCHcode test(char *URL)
{
  FETCHcode res;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  res = test_once(URL, TRUE); /* old */
  if (!res)
    res = test_once(URL, FALSE); /* new */

  fetch_global_cleanup();

  return res;
}
