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
/* <DESC>
 * Connection cache shared between easy handles with the share interface
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

static void my_lock(FETCH *handle, fetch_lock_data data,
                    fetch_lock_access laccess, void *useptr)
{
  (void)handle;
  (void)data;
  (void)laccess;
  (void)useptr;
  fprintf(stderr, "-> Mutex lock\n");
}

static void my_unlock(FETCH *handle, fetch_lock_data data, void *useptr)
{
  (void)handle;
  (void)data;
  (void)useptr;
  fprintf(stderr, "<- Mutex unlock\n");
}

int main(void)
{
  FETCHSH *share;
  int i;

  share = fetch_share_init();
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_CONNECT);

  fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, my_lock);
  fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, my_unlock);

  /* Loop the transfer and cleanup the handle properly every lap. This still
     reuses connections since the pool is in the shared object! */

  for(i = 0; i < 3; i++) {
    FETCH *fetch = fetch_easy_init();
    if(fetch) {
      FETCHcode res;

      fetch_easy_setopt(fetch, FETCHOPT_URL, "https://fetch.se/");

      /* use the share object */
      fetch_easy_setopt(fetch, FETCHOPT_SHARE, share);

      /* Perform the request, res gets the return code */
      res = fetch_easy_perform(fetch);
      /* Check for errors */
      if(res != FETCHE_OK)
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));

      /* always cleanup */
      fetch_easy_cleanup(fetch);
    }
  }

  fetch_share_cleanup(share);
  return 0;
}
