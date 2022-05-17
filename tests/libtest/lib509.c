/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <string.h>

/*
 * This test uses these funny custom memory callbacks for the only purpose
 * of verifying that curl_global_init_mem() functionality is present in
 * libcurl and that it works unconditionally no matter how libcurl is built,
 * nothing more.
 *
 * Do not include memdebug.h in this source file, and do not use directly
 * memory related functions in this file except those used inside custom
 * memory callbacks which should be calling 'the real thing'.
 */

static int seen;

static void *custom_calloc(size_t nmemb, size_t size)
{
  seen++;
  return (calloc)(nmemb, size);
}

static void *custom_malloc(size_t size)
{
  seen++;
  return (malloc)(size);
}

static char *custom_strdup(const char *ptr)
{
  seen++;
  return (strdup)(ptr);
}

static void *custom_realloc(void *ptr, size_t size)
{
  seen++;
  return (realloc)(ptr, size);
}

static void custom_free(void *ptr)
{
  seen++;
  (free)(ptr);
}


int test(char *URL)
{
  unsigned char a[] = {0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                       0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7};
  CURLcode res;
  CURL *curl;
  int asize;
  char *str = NULL;
  (void)URL;

  res = curl_global_init_mem(CURL_GLOBAL_ALL,
                             custom_malloc,
                             custom_free,
                             custom_realloc,
                             custom_strdup,
                             custom_calloc);
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_global_init_mem() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_USERAGENT, "test509"); /* uses strdup() */

  asize = (int)sizeof(a);
  str = curl_easy_escape(curl, (char *)a, asize); /* uses realloc() */

  if(seen)
    printf("Callbacks were invoked!\n");

test_cleanup:

  if(str)
    curl_free(str);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
