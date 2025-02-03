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

FETCHcode test(char *URL)
{
  FETCHM *multi;
  FETCH *easy;
  int running_handles;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  multi = fetch_multi_init();
  if(multi) {
    easy = fetch_easy_init();
    if(easy) {
      FETCHcode c;
      FETCHMcode m;

      /* Crash only happens when using HTTPS */
      c = fetch_easy_setopt(easy, FETCHOPT_URL, URL);
      if(!c)
        /* Any old HTTP tunneling proxy will do here */
        c = fetch_easy_setopt(easy, FETCHOPT_PROXY, libtest_arg2);

      if(!c) {

        /* We're going to drive the transfer using multi interface here,
           because we want to stop during the middle. */
        m = fetch_multi_add_handle(multi, easy);

        if(!m)
          /* Run the multi handle once, just enough to start establishing an
             HTTPS connection. */
          m = fetch_multi_perform(multi, &running_handles);

        if(m)
          fprintf(stderr, "fetch_multi_perform failed\n");
      }
      /* Close the easy handle *before* the multi handle. Doing it the other
         way around avoids the issue. */
      fetch_easy_cleanup(easy);
    }
    fetch_multi_cleanup(multi); /* double-free happens here */
  }
  fetch_global_cleanup();
  return FETCHE_OK;
}
