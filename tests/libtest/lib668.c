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

static char testdata[] = "dummy";

struct WriteThis
{
  char *readptr;
  fetch_off_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  size_t len = strlen(pooh->readptr);

  (void)size; /* Always 1.*/

  if (len > nmemb)
    len = nmemb;
  if (len)
  {
    memcpy(ptr, pooh->readptr, len);
    pooh->readptr += len;
  }
  return len;
}

FETCHcode test(char *URL)
{
  FETCH *easy = NULL;
  fetch_mime *mime = NULL;
  fetch_mimepart *part;
  FETCHcode res = TEST_ERR_FAILURE;
  struct WriteThis pooh1, pooh2;

  /*
   * Check early end of part data detection.
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

  /* Prepare the callback structures. */
  pooh1.readptr = testdata;
  pooh1.sizeleft = (fetch_off_t)strlen(testdata);
  pooh2 = pooh1;

  /* Build the mime tree. */
  mime = fetch_mime_init(easy);
  part = fetch_mime_addpart(mime);
  fetch_mime_name(part, "field1");
  /* Early end of data detection can be done because the data size is known. */
  fetch_mime_data_cb(part, (fetch_off_t)strlen(testdata),
                     read_callback, NULL, NULL, &pooh1);
  part = fetch_mime_addpart(mime);
  fetch_mime_name(part, "field2");
  /* Using an undefined length forces chunked transfer and disables early
     end of data detection for this part. */
  fetch_mime_data_cb(part, (fetch_off_t)-1, read_callback, NULL, NULL, &pooh2);
  part = fetch_mime_addpart(mime);
  fetch_mime_name(part, "field3");
  /* Regular file part sources early end of data can be detected because
     the file size is known. In addition, and EOF test is performed. */
  fetch_mime_filedata(part, libtest_arg2);

  /* Bind mime data to its easy handle. */
  test_setopt(easy, FETCHOPT_MIMEPOST, mime);

  /* Send data. */
  res = fetch_easy_perform(easy);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_perform() failed\n");
  }

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_mime_free(mime);
  fetch_global_cleanup();
  return res;
}
