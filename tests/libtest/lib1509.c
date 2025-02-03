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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

size_t WriteOutput(char *ptr, size_t size, size_t nmemb, void *stream);
size_t WriteHeader(char *ptr, size_t size, size_t nmemb, void *stream);

static unsigned long realHeaderSize = 0;

FETCHcode test(char *URL)
{
  long headerSize;
  FETCHcode code;
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_PROXY, libtest_arg2); /* set in first.c */

  easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, *WriteOutput);
  easy_setopt(fetch, FETCHOPT_HEADERFUNCTION, *WriteHeader);

  easy_setopt(fetch, FETCHOPT_HEADER, 1L);
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_HTTPPROXYTUNNEL, 1L);

  code = fetch_easy_perform(fetch);
  if(FETCHE_OK != code) {
    fprintf(stderr, "%s:%d fetch_easy_perform() failed, "
            "with code %d (%s)\n",
            __FILE__, __LINE__, code, fetch_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  code = fetch_easy_getinfo(fetch, FETCHINFO_HEADER_SIZE, &headerSize);
  if(FETCHE_OK != code) {
    fprintf(stderr, "%s:%d fetch_easy_getinfo() failed, "
            "with code %d (%s)\n",
            __FILE__, __LINE__, code, fetch_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  printf("header length is ........: %ld\n", headerSize);
  printf("header length should be..: %lu\n", realHeaderSize);

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

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

  realHeaderSize += fetchx_uztoul(size * nmemb);

  return nmemb * size;
}
