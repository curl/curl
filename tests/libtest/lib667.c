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

static char testdata[]=
  "dummy";

struct WriteThis {
  char *readptr;
  fetch_off_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  int eof = !*pooh->readptr;

  if(size*nmemb < 1)
    return 0;

  eof = pooh->sizeleft <= 0;
  if(!eof)
    pooh->sizeleft--;

  if(!eof) {
    *ptr = *pooh->readptr;           /* copy one single byte */
    pooh->readptr++;                 /* advance pointer */
    return 1;                        /* we return 1 byte at a time! */
  }

  return 0;                         /* no more data left to deliver */
}

FETCHcode test(char *URL)
{
  FETCH *easy = NULL;
  fetch_mime *mime = NULL;
  fetch_mimepart *part;
  FETCHcode res = TEST_ERR_FAILURE;
  struct WriteThis pooh;

  /*
   * Check proper handling of mime encoder feature when the part read callback
   * delivers data bytes one at a time. Use chunked encoding for accurate test.
   */

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
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
  pooh.sizeleft = (fetch_off_t) strlen(testdata);

  /* Build the mime tree. */
  mime = fetch_mime_init(easy);
  part = fetch_mime_addpart(mime);
  fetch_mime_name(part, "field");
  fetch_mime_encoder(part, "base64");
  /* Using an undefined length forces chunked transfer. */
  fetch_mime_data_cb(part, (fetch_off_t) -1, read_callback, NULL, NULL, &pooh);

  /* Bind mime data to its easy handle. */
  test_setopt(easy, FETCHOPT_MIMEPOST, mime);

  /* Send data. */
  res = fetch_easy_perform(easy);
  if(res != FETCHE_OK) {
    fprintf(stderr, "fetch_easy_perform() failed\n");
  }

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_mime_free(mime);
  fetch_global_cleanup();
  return res;
}
