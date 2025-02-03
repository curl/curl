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

static char testbuf[17000]; /* more than 16K */

FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;
  fetch_mime *mime = NULL;
  fetch_mimepart *part;
  size_t i;

  /* Checks huge binary-encoded mime post. */

  /* Create a testbuf with pseudo-binary data. */
  for (i = 0; i < sizeof(testbuf); i++)
    if (i % 77 == 76)
      testbuf[i] = '\n';
    else
      testbuf[i] = (char)(0x41 + i % 26); /* A...Z */

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Build mime structure. */
  mime = fetch_mime_init(fetch);
  if (!mime)
  {
    fprintf(stderr, "fetch_mime_init() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  part = fetch_mime_addpart(mime);
  if (!part)
  {
    fprintf(stderr, "fetch_mime_addpart() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  res = fetch_mime_name(part, "upfile");
  if (res)
  {
    fprintf(stderr, "fetch_mime_name() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_filename(part, "myfile.txt");
  if (res)
  {
    fprintf(stderr, "fetch_mime_filename() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_data(part, testbuf, sizeof(testbuf));
  if (res)
  {
    fprintf(stderr, "fetch_mime_data() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_encoder(part, "binary");
  if (res)
  {
    fprintf(stderr, "fetch_mime_encoder() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our mime mail. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Post form */
  test_setopt(fetch, FETCHOPT_MIMEPOST, mime);

  /* Shorten upload buffer. */
  test_setopt(fetch, FETCHOPT_UPLOAD_BUFFERSIZE, 16411L);

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);

  /* now cleanup the mime structure */
  fetch_mime_free(mime);

  fetch_global_cleanup();

  return res;
}
