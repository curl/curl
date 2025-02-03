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
    "dummy\n";

struct WriteThis
{
  char *readptr;
  fetch_off_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  int eof = !*pooh->readptr;

  if (size * nmemb < 1)
    return 0;

#ifndef LIB645
  eof = pooh->sizeleft <= 0;
  if (!eof)
    pooh->sizeleft--;
#endif

  if (!eof)
  {
    *ptr = *pooh->readptr; /* copy one single byte */
    pooh->readptr++;       /* advance pointer */
    return 1;              /* we return 1 byte at a time! */
  }

  return 0; /* no more data left to deliver */
}

static FETCHcode test_once(char *URL, bool oldstyle)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch_mime *mime = NULL;
  fetch_mimepart *part = NULL;
  struct WriteThis pooh;
  struct WriteThis pooh2;
  fetch_off_t datasize = -1;

  pooh.readptr = testdata;
#ifndef LIB645
  datasize = (fetch_off_t)strlen(testdata);
#endif
  pooh.sizeleft = datasize;

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  mime = fetch_mime_init(fetch);
  if (!mime)
  {
    fprintf(stderr, "fetch_mime_init() failed\n");
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart(1) failed\n");
    fetch_mime_free(mime);
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the file upload part */
  if (oldstyle)
  {
    res = fetch_mime_name(part, "sendfile");
    if (!res)
      res = fetch_mime_data_cb(part, datasize, read_callback,
                               NULL, NULL, &pooh);
    if (!res)
      res = fetch_mime_filename(part, "postit2.c");
  }
  else
  {
    /* new style */
    res = fetch_mime_name(part, "sendfile alternative");
    if (!res)
      res = fetch_mime_data_cb(part, datasize, read_callback,
                               NULL, NULL, &pooh);
    if (!res)
      res = fetch_mime_filename(part, "file name 2");
  }

  if (res)
    printf("fetch_mime_xxx(1) = %s\n", fetch_easy_strerror(res));

  /* Now add the same data with another name and make it not look like
     a file upload but still using the callback */

  pooh2.readptr = testdata;
#ifndef LIB645
  datasize = (fetch_off_t)strlen(testdata);
#endif
  pooh2.sizeleft = datasize;

  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart(2) failed\n");
    fetch_mime_free(mime);
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  /* Fill in the file upload part */
  res = fetch_mime_name(part, "callbackdata");
  if (!res)
    res = fetch_mime_data_cb(part, datasize, read_callback,
                             NULL, NULL, &pooh2);

  if (res)
    printf("fetch_mime_xxx(2) = %s\n", fetch_easy_strerror(res));

  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart(3) failed\n");
    fetch_mime_free(mime);
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the filename field */
  res = fetch_mime_name(part, "filename");
  if (!res)
    res = fetch_mime_data(part, "postit2.c",
                          FETCH_ZERO_TERMINATED);

  if (res)
    printf("fetch_mime_xxx(3) = %s\n", fetch_easy_strerror(res));

  /* Fill in a submit field too */
  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart(4) failed\n");
    fetch_mime_free(mime);
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  res = fetch_mime_name(part, "submit");
  if (!res)
    res = fetch_mime_data(part, "send",
                          FETCH_ZERO_TERMINATED);

  if (res)
    printf("fetch_mime_xxx(4) = %s\n", fetch_easy_strerror(res));

  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart(5) failed\n");
    fetch_mime_free(mime);
    fetch_easy_cleanup(fetch);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  res = fetch_mime_name(part, "somename");
  if (!res)
    res = fetch_mime_filename(part, "somefile.txt");
  if (!res)
    res = fetch_mime_data(part, "blah blah", 9);

  if (res)
    printf("fetch_mime_xxx(5) = %s\n", fetch_easy_strerror(res));

  /* First set the URL that is about to receive our POST. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* send a multi-part mimepost */
  test_setopt(fetch, FETCHOPT_MIMEPOST, mime);

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);

  /* now cleanup the mimepost structure */
  fetch_mime_free(mime);

  return res;
}

static FETCHcode cyclic_add(void)
{
  FETCH *easy = fetch_easy_init();
  fetch_mime *mime = fetch_mime_init(easy);
  fetch_mimepart *part = fetch_mime_addpart(mime);
  FETCHcode a1 = fetch_mime_subparts(part, mime);

  if (a1 == FETCHE_BAD_FUNCTION_ARGUMENT)
  {
    fetch_mime *submime = fetch_mime_init(easy);
    fetch_mimepart *subpart = fetch_mime_addpart(submime);

    fetch_mime_subparts(part, submime);
    a1 = fetch_mime_subparts(subpart, mime);
  }

  fetch_mime_free(mime);
  fetch_easy_cleanup(easy);
  if (a1 != FETCHE_BAD_FUNCTION_ARGUMENT)
    /* that should have failed */
    return (FETCHcode)1;

  return FETCHE_OK;
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

  if (!res)
    res = cyclic_add();

  fetch_global_cleanup();

  return res;
}
