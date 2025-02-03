/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

#define TEST_HANG_TIMEOUT 60 * 1000

#define NUM_URLS 4

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch = NULL;
  int i;
  char target_url[256];
  char dnsentry[256];
  struct fetch_slist *slist = NULL, *slist2;
  char *port = libtest_arg3;
  char *address = libtest_arg2;

  (void)URL;

  /* Create fake DNS entries for serverX.example.com for all handles */
  for (i = 0; i < NUM_URLS; i++)
  {
    msnprintf(dnsentry, sizeof(dnsentry), "server%d.example.com:%s:%s", i + 1,
              port, address);
    printf("%s\n", dnsentry);
    slist2 = fetch_slist_append(slist, dnsentry);
    if (!slist2)
    {
      fprintf(stderr, "fetch_slist_append() failed\n");
      goto test_cleanup;
    }
    slist = slist2;
  }

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  /* get an easy handle */
  easy_init(fetch);

  /* go verbose */
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  /* include headers */
  easy_setopt(fetch, FETCHOPT_HEADER, 1L);

  easy_setopt(fetch, FETCHOPT_RESOLVE, slist);

  easy_setopt(fetch, FETCHOPT_MAXCONNECTS, 3L);

  /* get NUM_HANDLES easy handles */
  for (i = 0; i < NUM_URLS; i++)
  {
    /* specify target */
    msnprintf(target_url, sizeof(target_url),
              "http://server%d.example.com:%s/path/1510%04i",
              i + 1, port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(fetch, FETCHOPT_URL, target_url);

    res = fetch_easy_perform(fetch);
    if (res)
      goto test_cleanup;

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  fetch_easy_cleanup(fetch);

  fetch_slist_free_all(slist);

  fetch_global_cleanup();

  return res;
}
