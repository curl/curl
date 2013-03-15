/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define VERBOSE 0

size_t WriteOutput(void *ptr, size_t size, size_t nmemb, void *stream);
size_t WriteHeader(void *ptr, size_t size, size_t nmemb, void *stream);

long realHeaderSize = 0;

int test(char *URL)
{
  CURL *curl;
  long headerSize;
  CURLcode res=CURLE_OK;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  easy_setopt(curl, CURLOPT_PROXY, libtest_arg2); /* set in first.c */

  easy_setopt(curl, CURLOPT_WRITEFUNCTION, *WriteOutput);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, *WriteHeader);

  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
  res = curl_easy_perform(curl);

  curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &headerSize);
  printf("header length is ........: %lu\n", headerSize);
  printf("header length should be..: %lu\n", realHeaderSize);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return (int)res;
}

size_t WriteOutput(void *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return nmemb * size;
}

size_t WriteHeader(void *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)ptr;
  (void)stream;
  realHeaderSize += size * nmemb;

  return nmemb * size;
}
