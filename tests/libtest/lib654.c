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
    "dummy\n";

struct WriteThis
{
  char *readptr;
  fetch_off_t sizeleft;
  int freecount;
};

static void free_callback(void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;

  pooh->freecount++;
}

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  int eof = !*pooh->readptr;

  if (size * nmemb < 1)
    return 0;

  eof = pooh->sizeleft <= 0;
  if (!eof)
    pooh->sizeleft--;

  if (!eof)
  {
    *ptr = *pooh->readptr; /* copy one single byte */
    pooh->readptr++;       /* advance pointer */
    return 1;              /* we return 1 byte at a time! */
  }

  return 0; /* no more data left to deliver */
}

FETCHcode test(char *URL)
{
  FETCH *easy = NULL;
  FETCH *easy2 = NULL;
  fetch_mime *mime = NULL;
  fetch_mimepart *part;
  struct fetch_slist *hdrs = NULL;
  FETCHcode res = TEST_ERR_FAILURE;
  struct WriteThis pooh;

  /*
   * Check proper copy/release of mime post data bound to a duplicated
   * easy handle.
   */

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  easy = fetch_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(easy, FETCHOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(easy, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(easy, FETCHOPT_HEADER, 1L);

  /* Prepare the callback structure. */
  pooh.readptr = testdata;
  pooh.sizeleft = (fetch_off_t)strlen(testdata);
  pooh.freecount = 0;

  /* Build the mime tree. */
  mime = fetch_mime_init(easy);
  part = fetch_mime_addpart(mime);
  fetch_mime_data(part, "hello", FETCH_ZERO_TERMINATED);
  fetch_mime_name(part, "greeting");
  fetch_mime_type(part, "application/X-Greeting");
  fetch_mime_encoder(part, "base64");
  hdrs = fetch_slist_append(hdrs, "X-Test-Number: 654");
  fetch_mime_headers(part, hdrs, TRUE);
  part = fetch_mime_addpart(mime);
  fetch_mime_filedata(part, libtest_arg2);
  part = fetch_mime_addpart(mime);
  fetch_mime_data_cb(part, (fetch_off_t)-1, read_callback, NULL, free_callback,
                     &pooh);

  /* Bind mime data to its easy handle. */
  test_setopt(easy, FETCHOPT_MIMEPOST, mime);

  /* Duplicate the handle. */
  easy2 = fetch_easy_duphandle(easy);
  if (!easy2)
  {
    fprintf(stderr, "fetch_easy_duphandle() failed\n");
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* Now free the mime structure: it should unbind it from the first
     easy handle. */
  fetch_mime_free(mime);
  mime = NULL; /* Already cleaned up. */

  /* Perform on the first handle: should not send any data. */
  res = fetch_easy_perform(easy);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_perform(original) failed\n");
    goto test_cleanup;
  }

  /* Perform on the second handle: if the bound mime structure has not been
     duplicated properly, it should cause a valgrind error. */
  res = fetch_easy_perform(easy2);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_perform(duplicated) failed\n");
    goto test_cleanup;
  }

  /* Free the duplicated handle: it should call free_callback again.
     If the mime copy was bad or not automatically released, valgrind
     will signal it. */
  fetch_easy_cleanup(easy2);
  easy2 = NULL; /* Already cleaned up. */

  if (pooh.freecount != 2)
  {
    fprintf(stderr, "free_callback() called %d times instead of 2\n",
            pooh.freecount);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_easy_cleanup(easy2);
  fetch_mime_free(mime);
  fetch_global_cleanup();
  return res;
}
