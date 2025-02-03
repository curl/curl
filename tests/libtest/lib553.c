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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/* This test case and code is based on the bug recipe Joe Malicki provided for
 * bug report #1871269, fixed on Jan 14 2008 before the 7.18.0 release.
 */

#include "test.h"

#include "memdebug.h"

#define POSTLEN 40960

static size_t myreadfunc(char *ptr, size_t size, size_t nmemb, void *stream)
{
  static size_t total = POSTLEN;
  static char buf[1024];
  (void)stream;

  memset(buf, 'A', sizeof(buf));

  size *= nmemb;
  if (size > total)
    size = total;

  if (size > sizeof(buf))
    size = sizeof(buf);

  memcpy(ptr, buf, size);
  total -= size;
  return size;
}

#define NUM_HEADERS 8
#define SIZE_HEADERS 5000

static char testbuf[SIZE_HEADERS + 100];

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_FAILED_INIT;
  int i;
  struct fetch_slist *headerlist = NULL, *hl;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  for (i = 0; i < NUM_HEADERS; i++)
  {
    int len = msnprintf(testbuf, sizeof(testbuf), "Header%d: ", i);
    memset(&testbuf[len], 'A', SIZE_HEADERS);
    testbuf[len + SIZE_HEADERS] = 0; /* null-terminate */
    hl = fetch_slist_append(headerlist, testbuf);
    if (!hl)
      goto test_cleanup;
    headerlist = hl;
  }

  hl = fetch_slist_append(headerlist, "Expect: ");
  if (!hl)
    goto test_cleanup;
  headerlist = hl;

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, headerlist);
  test_setopt(fetch, FETCHOPT_POST, 1L);
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)POSTLEN);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_READFUNCTION, myreadfunc);

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);

  fetch_slist_free_all(headerlist);

  fetch_global_cleanup();

  return res;
}
