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
/* <DESC>
 * using the multi interface to do a single download
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

/* fetch stuff */
#include <fetch/fetch.h>

/*
 * Simply download an HTTP file.
 */
int main(void)
{
  FETCH *http_handle;
  FETCHM *multi_handle;
  int still_running = 1; /* keep number of running handles */

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  http_handle = fetch_easy_init();

  /* set the options (I left out a few, you get the point anyway) */
  fetch_easy_setopt(http_handle, FETCHOPT_URL, "https://www.example.com/");

  /* init a multi stack */
  multi_handle = fetch_multi_init();

  /* add the individual transfers */
  fetch_multi_add_handle(multi_handle, http_handle);

  do
  {
    FETCHMcode mc = fetch_multi_perform(multi_handle, &still_running);

    if (!mc)
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(multi_handle, NULL, 0, 1000, NULL);

    if (mc)
    {
      fprintf(stderr, "fetch_multi_poll() failed, code %d.\n", (int)mc);
      break;
    }

  } while (still_running);

  fetch_multi_remove_handle(multi_handle, http_handle);

  fetch_easy_cleanup(http_handle);

  fetch_multi_cleanup(multi_handle);

  fetch_global_cleanup();

  return 0;
}
