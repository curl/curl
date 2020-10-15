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

/* This test case and code is based on the bug recipe Joe Malicki provided for
 * bug report #1871269, fixed on Jan 14 2008 before the 7.18.0 release.
 */

#include "test.h"

#include "memdebug.h"

#define POSTLEN 40960

static size_t myreadfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  static size_t total = POSTLEN;
  static char buf[1024];
  (void)stream;

  memset(buf, 'A', sizeof(buf));

  size *= nmemb;
  if(size > total)
    size = total;

  if(size > sizeof(buf))
    size = sizeof(buf);

  memcpy(ptr, buf, size);
  total -= size;
  return size;
}

#define NUM_HEADERS 8
#define SIZE_HEADERS 5000

static char buf[SIZE_HEADERS + 100];

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_FAILED_INIT;
  int i;
  struct curl_slist *headerlist = NULL, *hl;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < NUM_HEADERS; i++) {
    int len = msnprintf(buf, sizeof(buf), "Header%d: ", i);
    memset(&buf[len], 'A', SIZE_HEADERS);
    buf[len + SIZE_HEADERS] = 0; /* null-terminate */
    hl = curl_slist_append(headerlist,  buf);
    if(!hl)
      goto test_cleanup;
    headerlist = hl;
  }

  hl = curl_slist_append(headerlist, "Expect: ");
  if(!hl)
    goto test_cleanup;
  headerlist = hl;

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  test_setopt(curl, CURLOPT_POST, 1L);
#ifdef CURL_DOES_CONVERSIONS
  /* Convert the POST data to ASCII */
  test_setopt(curl, CURLOPT_TRANSFERTEXT, 1L);
#endif
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)POSTLEN);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_READFUNCTION, myreadfunc);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);

  curl_slist_free_all(headerlist);

  curl_global_cleanup();

  return (int)res;
}
