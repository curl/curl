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

size_t WriteOutput(char *ptr, size_t size, size_t nmemb, void *stream);
size_t WriteHeader(char *ptr, size_t size, size_t nmemb, void *stream);

static unsigned long realHeaderSize = 0;

static CURLcode test_lib1509(char *URL)
{
  long headerSize;
  CURLcode code;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_PROXY, libtest_arg2); /* set in first.c */

  easy_setopt(curl, CURLOPT_WRITEFUNCTION, *WriteOutput);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, *WriteHeader);

  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);

  code = curl_easy_perform(curl);
  if(CURLE_OK != code) {
    curl_mfprintf(stderr, "%s:%d curl_easy_perform() failed, "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, code, curl_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  code = curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &headerSize);
  if(CURLE_OK != code) {
    curl_mfprintf(stderr, "%s:%d curl_easy_getinfo() failed, "
                  "with code %d (%s)\n",
                  __FILE__, __LINE__, code, curl_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_mprintf("header length is ........: %ld\n", headerSize);
  curl_mprintf("header length should be..: %lu\n", realHeaderSize);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

size_t WriteOutput(char *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return nmemb * size;
}

size_t WriteHeader(char *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)ptr;
  (void)stream;

  realHeaderSize += curlx_uztoul(size * nmemb);

  return nmemb * size;
}
