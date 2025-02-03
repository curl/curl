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
  struct fetch_slist *recipients = NULL;

  /* create a testbuf with AAAA...BBBBB...CCCC...etc */
  int i;
  int size = (int)sizeof(testbuf) / 10;

  for (i = 0; i < size; i++)
    memset(&testbuf[i * 10], 65 + (i % 26), 10);

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
  res = fetch_mime_filename(part, "myfile.jpg");
  if (res)
  {
    fprintf(stderr, "fetch_mime_filename() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_type(part, "image/jpeg");
  if (res)
  {
    fprintf(stderr, "fetch_mime_type() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_data(part, testbuf, sizeof(testbuf));
  if (res)
  {
    fprintf(stderr, "fetch_mime_data() failed\n");
    goto test_cleanup;
  }
  res = fetch_mime_encoder(part, "base64");
  if (res)
  {
    fprintf(stderr, "fetch_mime_encoder() failed\n");
    goto test_cleanup;
  }

  /* Prepare recipients. */
  recipients = fetch_slist_append(NULL, "someone@example.com");
  if (!recipients)
  {
    fprintf(stderr, "fetch_slist_append() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our mime mail. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Set sender. */
  test_setopt(fetch, FETCHOPT_MAIL_FROM, "somebody@example.com");

  /* Set recipients. */
  test_setopt(fetch, FETCHOPT_MAIL_RCPT, recipients);

  /* send a multi-part mail */
  test_setopt(fetch, FETCHOPT_MIMEPOST, mime);

  /* Shorten upload buffer. */
  test_setopt(fetch, FETCHOPT_UPLOAD_BUFFERSIZE, 16411L);

  /* get verbose debug output please */
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);

  /* now cleanup the mime structure */
  fetch_mime_free(mime);

  /* cleanup the recipients. */
  fetch_slist_free_all(recipients);

  fetch_global_cleanup();

  return res;
}
