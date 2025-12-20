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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

struct t654_WriteThis {
  const char *readptr;
  curl_off_t sizeleft;
  int freecount;
};

static void free_callback(void *userp)
{
  struct t654_WriteThis *pooh = (struct t654_WriteThis *)userp;

  pooh->freecount++;
}

static size_t t654_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t654_WriteThis *pooh = (struct t654_WriteThis *)userp;
  int eof;

  if(size * nmemb < 1)
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

static CURLcode test_lib654(const char *URL)
{
  static const char testdata[] = "dummy\n";

  CURL *curl = NULL;
  CURL *curl2 = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part;
  struct curl_slist *hdrs = NULL;
  CURLcode result = TEST_ERR_FAILURE;
  struct t654_WriteThis pooh;

  /*
   * Check proper copy/release of mime post data bound to a duplicated
   * easy handle.
   */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Prepare the callback structure. */
  pooh.readptr = testdata;
  pooh.sizeleft = (curl_off_t)strlen(testdata);
  pooh.freecount = 0;

  /* Build the mime tree. */
  mime = curl_mime_init(curl);
  part = curl_mime_addpart(mime);
  curl_mime_data(part, "hello", CURL_ZERO_TERMINATED);
  curl_mime_name(part, "greeting");
  curl_mime_type(part, "application/X-Greeting");
  curl_mime_encoder(part, "base64");
  hdrs = curl_slist_append(hdrs, "X-Test-Number: 654");
  curl_mime_headers(part, hdrs, TRUE);
  part = curl_mime_addpart(mime);
  curl_mime_filedata(part, libtest_arg2);
  part = curl_mime_addpart(mime);
  curl_mime_data_cb(part, (curl_off_t)-1, t654_read_cb, NULL,
                    free_callback, &pooh);

  /* Bind mime data to its easy handle. */
  test_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* Duplicate the handle. */
  curl2 = curl_easy_duphandle(curl);
  if(!curl2) {
    curl_mfprintf(stderr, "curl_easy_duphandle() failed\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* Now free the mime structure: it should unbind it from the first
     easy handle. */
  curl_mime_free(mime);
  mime = NULL;  /* Already cleaned up. */

  /* Perform on the first handle: should not send any data. */
  result = curl_easy_perform(curl);
  if(result != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_perform(original) failed\n");
    goto test_cleanup;
  }

  /* Perform on the second handle: if the bound mime structure has not been
     duplicated properly, it should cause a valgrind error. */
  result = curl_easy_perform(curl2);
  if(result != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_perform(duplicated) failed\n");
    goto test_cleanup;
  }

  /* Free the duplicated handle: it should call free_callback again.
     If the mime copy was bad or not automatically released, valgrind
     will signal it. */
  curl_easy_cleanup(curl2);
  curl2 = NULL;  /* Already cleaned up. */

  if(pooh.freecount != 2) {
    curl_mfprintf(stderr, "free_callback() called %d times instead of 2\n",
                  pooh.freecount);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_easy_cleanup(curl2);
  curl_mime_free(mime);
  curl_global_cleanup();
  return result;
}
