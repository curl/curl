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
 * are also available at https://fetch.haxx.se/docs/copyright.html.
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

#include "memdebug.h"

static size_t writecb(char *data, size_t n, size_t l, void *userp)
{
  /* ignore the data */
  (void)data;
  (void)userp;
  return n*l;
}
FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  struct fetch_header *h;
  int count = 0;
  unsigned int origins;

  global_init(FETCH_GLOBAL_DEFAULT);

  easy_init(fetch);

  /* perform a request that involves redirection */
  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);
  easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform() failed: %s\n",
            fetch_easy_strerror(res));
    goto test_cleanup;
  }

  /* count the number of requests by reading the first header of each
     request. */
  origins = (FETCHH_HEADER|FETCHH_TRAILER|FETCHH_CONNECT|
             FETCHH_1XX|FETCHH_PSEUDO);
  do {
    h = fetch_easy_nextheader(fetch, origins, count, NULL);
    if(h)
      count++;
  } while(h);
  printf("count = %u\n", count);

  /* perform another request - without redirect */
  easy_setopt(fetch, FETCHOPT_URL, libtest_arg2);
  res = fetch_easy_perform(fetch);
  if(res) {
    fprintf(stderr, "fetch_easy_perform() failed: %s\n",
            fetch_easy_strerror(res));
    goto test_cleanup;
  }

  /* count the number of requests again. */
  count = 0;
  do {
    h = fetch_easy_nextheader(fetch, origins, count, NULL);
    if(h)
      count++;
  } while(h);
  printf("count = %u\n", count);

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
