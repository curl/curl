/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

static char data[]=
#ifdef CURL_DOES_CONVERSIONS
  /* ASCII representation with escape sequences for non-ASCII platforms */
  "\x64\x75\x6d\x6d\x79";
#else
  "dummy";
#endif

struct WriteThis {
  char *readptr;
  curl_off_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  size_t len = strlen(pooh->readptr);

  (void) size; /* Always 1.*/

  if(len > nmemb)
    len = nmemb;
  if(len) {
    memcpy(ptr, pooh->readptr, len);
    pooh->readptr += len;
  }
  return len;
}

int test(char *URL)
{
  CURL *easy = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part;
  CURLcode result;
  int res = TEST_ERR_FAILURE;
  struct WriteThis pooh1, pooh2;

  /*
   * Check early end of part data detection.
   */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  easy = curl_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(easy, CURLOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(easy, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(easy, CURLOPT_HEADER, 1L);

  /* Prepare the callback structures. */
  pooh1.readptr = data;
  pooh1.sizeleft = (curl_off_t) strlen(data);
  pooh2 = pooh1;

  /* Build the mime tree. */
  mime = curl_mime_init(easy);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "field1");
  /* Early end of data detection can be done because the data size is known. */
  curl_mime_data_cb(part, (curl_off_t) strlen(data),
                    read_callback, NULL, NULL, &pooh1);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "field2");
  /* Using an undefined length forces chunked transfer and disables early
     end of data detection for this part. */
  curl_mime_data_cb(part, (curl_off_t) -1, read_callback, NULL, NULL, &pooh2);
  part = curl_mime_addpart(mime);
  curl_mime_name(part, "field3");
  /* Regular file part sources early end of data can be detected because
     the file size is known. In addition, and EOF test is performed. */
  curl_mime_filedata(part, "log/file668.txt");

  /* Bind mime data to its easy handle. */
  test_setopt(easy, CURLOPT_MIMEPOST, mime);

  /* Send data. */
  result = curl_easy_perform(easy);
  if(result) {
    fprintf(stderr, "curl_easy_perform() failed\n");
    res = (int) result;
  }

test_cleanup:
  curl_easy_cleanup(easy);
  curl_mime_free(mime);
  curl_global_cleanup();
  return res;
}
