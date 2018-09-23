/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
#include "memdebug.h"
*/

static int seen_malloc = 0;
static int seen_free = 0;
static int seen_realloc = 0;
static int seen_strdup = 0;
static int seen_calloc = 0;

void *custom_malloc(size_t size);
void custom_free(void *ptr);
void *custom_realloc(void *ptr, size_t size);
char *custom_strdup(const char *ptr);
void *custom_calloc(size_t nmemb, size_t size);


void *custom_calloc(size_t nmemb, size_t size)
{
  if(!seen_calloc) {
    printf("seen custom_calloc()\n");
    seen_calloc = 1;
  }
  return (calloc)(nmemb, size);
}

void *custom_malloc(size_t size)
{
  if(!seen_malloc && seen_calloc) {
    printf("seen custom_malloc()\n");
    seen_malloc = 1;
  }
  return (malloc)(size);
}

char *custom_strdup(const char *ptr)
{
  if(!seen_strdup && seen_malloc) {
    /* currently (2013.03.13), memory tracking enabled builds do not call
       the strdup callback, in this case malloc callback and memcpy are used
       instead. If some day this is changed the following printf() should be
       uncommented, and a line added to test definition.
    printf("seen custom_strdup()\n");
    */
    seen_strdup = 1;
  }
  return (strdup)(ptr);
}

void *custom_realloc(void *ptr, size_t size)
{
  if(!seen_realloc && seen_malloc) {
    printf("seen custom_realloc()\n");
    seen_realloc = 1;
  }
  return (realloc)(ptr, size);
}

void custom_free(void *ptr)
{
  if(!seen_free && seen_realloc) {
    printf("seen custom_free()\n");
    seen_free = 1;
  }
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

test_cleanup:

  if(str)
    curl_free(str);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
