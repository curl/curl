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
 * Get IMAP email with the multi interface
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to fetch mail using libfetch's IMAP
 * capabilities. It builds on the imap-fetch.c example to demonstrate how to
 * use libfetch's multi interface.
 */

int main(void)
{
  FETCH *fetch;
  FETCHM *mfetch;
  int still_running = 1;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if (!fetch)
    return 1;

  mfetch = fetch_multi_init();
  if (!mfetch)
    return 2;

  /* Set username and password */
  fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "user");
  fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "secret");

  /* This fetches message 1 from the user's inbox */
  fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://imap.example.com/INBOX/;UID=1");

  /* Tell the multi stack about our easy handle */
  fetch_multi_add_handle(mfetch, fetch);

  do
  {
    FETCHMcode mc = fetch_multi_perform(mfetch, &still_running);

    if (still_running)
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(mfetch, NULL, 0, 1000, NULL);

    if (mc)
      break;
  } while (still_running);

  /* Always cleanup */
  fetch_multi_remove_handle(mfetch, fetch);
  fetch_multi_cleanup(mfetch);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return 0;
}
