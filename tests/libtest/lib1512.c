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

/*
 * Use global DNS cache (while deprecated it should still work), populate it
 * with FETCHOPT_RESOLVE in the first request and then make sure a subsequent
 * easy transfer finds and uses the populated stuff.
 */

#include "test.h"

#include "memdebug.h"

#define NUM_HANDLES 2

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch[NUM_HANDLES] = {NULL, NULL};
  char *port = libtest_arg3;
  char *address = libtest_arg2;
  char dnsentry[256];
  struct fetch_slist *slist = NULL;
  int i;
  char target_url[256];
  (void)URL; /* URL is setup in the code */

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  msnprintf(dnsentry, sizeof(dnsentry), "server.example.fetch:%s:%s",
            port, address);
  printf("%s\n", dnsentry);
  slist = fetch_slist_append(slist, dnsentry);

  /* get NUM_HANDLES easy handles */
  for(i = 0; i < NUM_HANDLES; i++) {
    /* get an easy handle */
    easy_init(fetch[i]);
    /* specify target */
    msnprintf(target_url, sizeof(target_url),
              "http://server.example.fetch:%s/path/1512%04i",
              port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(fetch[i], FETCHOPT_URL, target_url);
    /* go verbose */
    easy_setopt(fetch[i], FETCHOPT_VERBOSE, 1L);
    /* include headers */
    easy_setopt(fetch[i], FETCHOPT_HEADER, 1L);

    FETCH_IGNORE_DEPRECATION(
      easy_setopt(fetch[i], FETCHOPT_DNS_USE_GLOBAL_CACHE, 1L);
    )
  }

  /* make the first one populate the GLOBAL cache */
  easy_setopt(fetch[0], FETCHOPT_RESOLVE, slist);

  /* run NUM_HANDLES transfers */
  for(i = 0; (i < NUM_HANDLES) && !res; i++) {
    res = fetch_easy_perform(fetch[i]);
    if(res)
      goto test_cleanup;
  }

test_cleanup:

  fetch_easy_cleanup(fetch[0]);
  fetch_easy_cleanup(fetch[1]);
  fetch_slist_free_all(slist);
  fetch_global_cleanup();

  return res;
}
