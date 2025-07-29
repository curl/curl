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

#include "memdebug.h"

struct headerinfo {
  size_t largest;
};

static size_t header(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t headersize = size * nmemb;
  struct headerinfo *info = (struct headerinfo *)stream;
  (void)ptr;

  if(headersize > info->largest)
    /* remember the longest header */
    info->largest = headersize;

  return nmemb * size;
}

static CURLcode test_lib1556(char *URL)
{
  CURLcode code;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  struct headerinfo info = {0};

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_HEADERFUNCTION, header);
  easy_setopt(curl, CURLOPT_HEADERDATA, &info);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_URL, URL);

  code = curl_easy_perform(curl);
  if(CURLE_OK != code) {
    curl_mfprintf(stderr, "%s:%d curl_easy_perform() failed, "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, code, curl_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_mprintf("Max = %ld\n", (long)info.largest);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
