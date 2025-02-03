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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static const char *chunks[] = {
    "one",
    "two",
    "three",
    "four",
    NULL};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  static int ix = 0;
  (void)size;
  (void)nmemb;
  (void)stream;
  if (chunks[ix])
  {
    size_t len = strlen(chunks[ix]);
    strcpy(ptr, chunks[ix]);
    ix++;
    return len;
  }
  return 0;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct fetch_slist *chunk = NULL;

  fetch_global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if (fetch)
  {
    /* deliberately setting the size - to a wrong value to make sure libfetch
       ignores it */
    easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, 4L);
    easy_setopt(fetch, FETCHOPT_POSTFIELDS, NULL);
    easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
    easy_setopt(fetch, FETCHOPT_POST, 1L);
    easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    easy_setopt(fetch, FETCHOPT_HTTP_VERSION, (long)FETCH_HTTP_VERSION_1_1);
    easy_setopt(fetch, FETCHOPT_URL, URL);
    easy_setopt(fetch, FETCHOPT_READDATA, NULL);

    chunk = fetch_slist_append(chunk, "Expect:");
    if (chunk)
    {
      struct fetch_slist *n =
          fetch_slist_append(chunk, "Transfer-Encoding: chunked");
      if (n)
        chunk = n;
      if (n)
        easy_setopt(fetch, FETCHOPT_HTTPHEADER, n);
    }

    res = fetch_easy_perform(fetch);
  }
test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_slist_free_all(chunk);

  fetch_global_cleanup();
  return res;
}
