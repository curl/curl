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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"



static const char *chunks[]={
  "one",
  "two",
  "three",
  "four",
  NULL
};


static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  static int ix = 0;
  (void)size;
  (void)nmemb;
  (void)stream;
  if(chunks[ix]) {
    size_t len = strlen(chunks[ix]);
    strcpy(ptr, chunks[ix]);
    ix++;
    return len;
  }
  return 0;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *chunk = NULL;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    /* deliberately setting the size - to a wrong value to make sure libcurl
       ignores it */
    easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 4L);
    easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);
    easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    easy_setopt(curl, CURLOPT_POST, 1L);
    easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    easy_setopt(curl, CURLOPT_URL, URL);
    easy_setopt(curl, CURLOPT_READDATA, NULL);

    chunk = curl_slist_append(chunk, "Expect:");
    if(chunk) {
      struct curl_slist *n =
        curl_slist_append(chunk, "Transfer-Encoding: chunked");
      if(n)
        chunk = n;
      if(n)
        easy_setopt(curl, CURLOPT_HTTPHEADER, n);
    }

    res = curl_easy_perform(curl);
  }
test_cleanup:
  curl_easy_cleanup(curl);
  curl_slist_free_all(chunk);

  curl_global_cleanup();
  return res;
}
