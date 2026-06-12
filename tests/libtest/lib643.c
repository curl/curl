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

struct t643_WriteThis {
  const char *readptr;
  curl_off_t sizeleft;
};

static size_t t643_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t643_WriteThis *pooh = (struct t643_WriteThis *)userp;
  int eof;

  if(size * nmemb < 1)
    return 0;

  if(testnum == 643) {
    eof = pooh->sizeleft <= 0;
    if(!eof)
      pooh->sizeleft--;
  }
  else {
    eof = !*pooh->readptr;
  }

  if(!eof) {
    *ptr = *pooh->readptr;           /* copy one single byte */
    pooh->readptr++;                 /* advance pointer */
    return 1;                        /* we return 1 byte at a time! */
  }

  return 0;                          /* no more data left to deliver */
}

static CURLcode t643_test_once(const char *URL, bool oldstyle)
{
  static const char testdata[] = "dummy\n";

  CURL *curl;
  CURLcode result = CURLE_OK;

  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  struct t643_WriteThis pooh;
  struct t643_WriteThis pooh2;
  curl_off_t datasize = -1;

  pooh.readptr = testdata;
  if(testnum == 643)
    datasize = (curl_off_t)strlen(testdata);
  pooh.sizeleft = datasize;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  mime = curl_mime_init(curl);
  if(!mime) {
    curl_mfprintf(stderr, "curl_mime_init() failed\n");
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart(1) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the file upload part */
  if(oldstyle) {
    result = curl_mime_name(part, "sendfile");
    if(!result)
      result = curl_mime_data_cb(part, datasize, t643_read_cb, NULL, NULL,
                                 &pooh);
    if(!result)
      result = curl_mime_filename(part, "postit2.c");
  }
  else {
    /* new style */
    result = curl_mime_name(part, "sendfile alternative");
    if(!result)
      result = curl_mime_data_cb(part, datasize, t643_read_cb, NULL, NULL,
                                 &pooh);
    if(!result)
      result = curl_mime_filename(part, "filename 2 ");
  }

  if(result)
    curl_mprintf("curl_mime_xxx(1) = %s\n", curl_easy_strerror(result));

  /* Now add the same data with another name and make it not look like
     a file upload but still using the callback */

  pooh2.readptr = testdata;
  if(testnum == 643)
    datasize = (curl_off_t)strlen(testdata);
  pooh2.sizeleft = datasize;

  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart(2) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  /* Fill in the file upload part */
  result = curl_mime_name(part, "callbackdata");
  if(!result)
    result = curl_mime_data_cb(part, datasize, t643_read_cb, NULL, NULL,
                               &pooh2);

  if(result)
    curl_mprintf("curl_mime_xxx(2) = %s\n", curl_easy_strerror(result));

  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart(3) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the filename field */
  result = curl_mime_name(part, "filename");
  if(!result)
    result = curl_mime_data(part, "postit2.c", CURL_ZERO_TERMINATED);

  if(result)
    curl_mprintf("curl_mime_xxx(3) = %s\n", curl_easy_strerror(result));

  /* Fill in a submit field too */
  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart(4) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  result = curl_mime_name(part, "submit");
  if(!result)
    result = curl_mime_data(part, "send", CURL_ZERO_TERMINATED);

  if(result)
    curl_mprintf("curl_mime_xxx(4) = %s\n", curl_easy_strerror(result));

  part = curl_mime_addpart(mime);
  if(!part) {
    curl_mfprintf(stderr, "curl_mime_addpart(5) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  result = curl_mime_name(part, "somename");
  if(!result)
    result = curl_mime_filename(part, "somefile.txt");
  if(!result)
    result = curl_mime_data(part, "blah blah", 9);

  if(result)
    curl_mprintf("curl_mime_xxx(5) = %s\n", curl_easy_strerror(result));

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* send a multi-part mimepost */
  test_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, result will get the return code */
  result = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  /* now cleanup the mimepost structure */
  curl_mime_free(mime);

  return result;
}

static CURLcode t643_cyclic_add(void)
{
  CURL *curl = curl_easy_init();
  curl_mime *mime = curl_mime_init(curl);
  curl_mimepart *part = curl_mime_addpart(mime);
  CURLcode result = curl_mime_subparts(part, mime);

  if(result == CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mime *submime = curl_mime_init(curl);
    curl_mimepart *subpart = curl_mime_addpart(submime);

    curl_mime_subparts(part, submime);
    result = curl_mime_subparts(subpart, mime);
  }

  curl_mime_free(mime);
  curl_easy_cleanup(curl);
  if(result != CURLE_BAD_FUNCTION_ARGUMENT)
    /* that should have failed */
    return TEST_ERR_FAILURE;

  return CURLE_OK;
}

static CURLcode test_lib643(const char *URL)
{
  CURLcode result;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  result = t643_test_once(URL, TRUE); /* old */
  if(!result)
    result = t643_test_once(URL, FALSE); /* new */

  if(!result)
    result = t643_cyclic_add();

  curl_global_cleanup();

  return result;
}
