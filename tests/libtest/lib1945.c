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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4706) /* assignment within conditional expression */
#endif
static void showem(FETCH *easy, unsigned int type)
{
  struct fetch_header *header = NULL;
  struct fetch_header *prev = NULL;

  while((header = fetch_easy_nextheader(easy, type, 0, prev))) {
    printf(" %s == %s (%u/%u)\n", header->name, header->value,
           (int)header->index, (int)header->amount);
    prev = header;
  }
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}
FETCHcode test(char *URL)
{
  FETCH *easy;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_DEFAULT);

  easy_init(easy);
  fetch_easy_setopt(easy, FETCHOPT_URL, URL);
  fetch_easy_setopt(easy, FETCHOPT_VERBOSE, 1L);
  fetch_easy_setopt(easy, FETCHOPT_FOLLOWLOCATION, 1L);
  /* ignores any content */
  fetch_easy_setopt(easy, FETCHOPT_WRITEFUNCTION, write_cb);

  /* if there's a proxy set, use it */
  if(libtest_arg2 && *libtest_arg2) {
    fetch_easy_setopt(easy, FETCHOPT_PROXY, libtest_arg2);
    fetch_easy_setopt(easy, FETCHOPT_HTTPPROXYTUNNEL, 1L);
  }
  res = fetch_easy_perform(easy);
  if(res) {
    printf("badness: %d\n", res);
  }
  showem(easy, FETCHH_CONNECT|FETCHH_HEADER|FETCHH_TRAILER|FETCHH_1XX);

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
  return res;
}
