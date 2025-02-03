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
#include "memdebug.h"

static const char *ldata_names[] = {
  "NONE",
  "SHARE",
  "COOKIE",
  "DNS",
  "SESSION",
  "CONNECT",
  "PSL",
  "HSTS",
  "NULL",
};

static void test_lock(FETCH *handle, fetch_lock_data data,
                      fetch_lock_access laccess, void *useptr)
{
  (void)handle;
  (void)data;
  (void)laccess;
  (void)useptr;
  printf("-> Mutex lock %s\n", ldata_names[data]);
}

static void test_unlock(FETCH *handle, fetch_lock_data data, void *useptr)
{
  (void)handle;
  (void)data;
  (void)useptr;
  printf("<- Mutex unlock %s\n", ldata_names[data]);
}

/* test function */
FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCHSH *share = NULL;
  int i;

  global_init(FETCH_GLOBAL_ALL);

  share = fetch_share_init();
  if(!share) {
    fprintf(stderr, "fetch_share_init() failed\n");
    goto test_cleanup;
  }

  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_CONNECT);
  fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, test_lock);
  fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, test_unlock);

  /* Loop the transfer and cleanup the handle properly every lap. This will
     still reuse connections since the pool is in the shared object! */

  for(i = 0; i < 3; i++) {
    FETCH *fetch = fetch_easy_init();
    if(fetch) {
      fetch_easy_setopt(fetch, FETCHOPT_URL, URL);

      /* use the share object */
      fetch_easy_setopt(fetch, FETCHOPT_SHARE, share);

      /* Perform the request, res will get the return code */
      res = fetch_easy_perform(fetch);

      /* always cleanup */
      fetch_easy_cleanup(fetch);

      /* Check for errors */
      if(res != FETCHE_OK) {
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));
        goto test_cleanup;
      }
    }
  }

test_cleanup:
  fetch_share_cleanup(share);
  fetch_global_cleanup();

  return res;
}
