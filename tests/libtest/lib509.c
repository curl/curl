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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include <string.h>

/*
 * This test uses these funny custom memory callbacks for the only purpose
 * of verifying that fetch_global_init_mem() functionality is present in
 * libfetch and that it works unconditionally no matter how libfetch is built,
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

FETCHcode test(char *URL)
{
  unsigned char a[] = {0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                       0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7};
  FETCHcode res;
  FETCH *fetch;
  int asize;
  char *str = NULL;
  (void)URL;

  res = fetch_global_init_mem(FETCH_GLOBAL_ALL,
                              custom_malloc,
                              custom_free,
                              custom_realloc,
                              custom_strdup,
                              custom_calloc);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init_mem() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_USERAGENT, "test509"); /* uses strdup() */

  asize = (int)sizeof(a);
  str = fetch_easy_escape(fetch, (char *)a, asize); /* uses realloc() */

  if (seen)
    printf("Callbacks were invoked!\n");

test_cleanup:

  if (str)
    fetch_free(str);

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
