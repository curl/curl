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

static const char *testdata[]={
  "daTE",
  "Server",
  "content-type",
  "content-length",
  "location",
  "set-cookie",
  "silly-thing",
  "fold",
  "blank",
  "Blank2",
  NULL
};

#ifdef LIB1946
#define HEADER_REQUEST 0
#else
#define HEADER_REQUEST -1
#endif

static void showem(FETCH *easy, unsigned int type)
{
  int i;
  struct fetch_header *header;
  for(i = 0; testdata[i]; i++) {
    if(FETCHHE_OK == fetch_easy_header(easy, testdata[i], 0, type,
                                     HEADER_REQUEST, &header)) {
      if(header->amount > 1) {
        /* more than one, iterate over them */
        size_t index = 0;
        size_t amount = header->amount;
        do {
          printf("- %s == %s (%u/%u)\n", header->name, header->value,
                 (int)index, (int)amount);

          if(++index == amount)
            break;
          if(FETCHHE_OK != fetch_easy_header(easy, testdata[i], index, type,
                                           HEADER_REQUEST, &header))
            break;
        } while(1);
      }
      else {
        /* only one of this */
        printf(" %s == %s\n", header->name, header->value);
      }
    }
  }
}

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n*l;
}
FETCHcode test(char *URL)
{
  FETCH *easy = NULL;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_DEFAULT);
  easy_init(easy);
  easy_setopt(easy, FETCHOPT_URL, URL);
  easy_setopt(easy, FETCHOPT_VERBOSE, 1L);
  easy_setopt(easy, FETCHOPT_FOLLOWLOCATION, 1L);
  /* ignores any content */
  easy_setopt(easy, FETCHOPT_WRITEFUNCTION, write_cb);

  /* if there's a proxy set, use it */
  if(libtest_arg2 && *libtest_arg2) {
    easy_setopt(easy, FETCHOPT_PROXY, libtest_arg2);
    easy_setopt(easy, FETCHOPT_HTTPPROXYTUNNEL, 1L);
  }
  res = fetch_easy_perform(easy);
  if(res)
    goto test_cleanup;

  showem(easy, FETCHH_HEADER);
  if(libtest_arg2 && *libtest_arg2) {
    /* now show connect headers only */
    showem(easy, FETCHH_CONNECT);
  }
  showem(easy, FETCHH_1XX);
  showem(easy, FETCHH_TRAILER);

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
  return res;
}
