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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

static char buffer[17000]; /* more than 16K */

int test(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  curl_mime *mime = NULL;
  curl_mimepart *part;
  struct curl_slist *recipients = NULL;

  /* create a buffer with AAAA...BBBBB...CCCC...etc */
  int i;
  int size = (int)sizeof(buffer) / 10;

  for(i = 0; i < size ; i++)
    memset(&buffer[i * 10], 65 + (i % 26), 10);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    res = (CURLcode) TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Build mime structure. */
  mime = curl_mime_init(curl);
  if(!mime) {
    fprintf(stderr, "curl_mime_init() failed\n");
    res = (CURLcode) TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart() failed\n");
    res = (CURLcode) TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  res = curl_mime_filename(part, "myfile.jpg");
  if(res) {
    fprintf(stderr, "curl_mime_filename() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_type(part, "image/jpeg");
  if(res) {
    fprintf(stderr, "curl_mime_type() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_data(part, buffer, sizeof(buffer));
  if(res) {
    fprintf(stderr, "curl_mime_data() failed\n");
    goto test_cleanup;
  }
  res = curl_mime_encoder(part, "base64");
  if(res) {
    fprintf(stderr, "curl_mime_encoder() failed\n");
    goto test_cleanup;
  }

  /* Prepare recipients. */
  recipients = curl_slist_append(NULL, "someone@example.com");
  if(!recipients) {
    fprintf(stderr, "curl_slist_append() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our mime mail. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* Set sender. */
  test_setopt(curl, CURLOPT_MAIL_FROM, "somebody@example.com");

  /* Set recipients. */
  test_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

  /* send a multi-part mail */
  test_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* Shorten upload buffer. */
  test_setopt(curl, CURLOPT_UPLOAD_BUFFERSIZE, 16411L);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  /* now cleanup the mime structure */
  curl_mime_free(mime);

  /* cleanup the recipients. */
  curl_slist_free_all(recipients);

  curl_global_cleanup();

  return res;
}
