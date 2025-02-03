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
 * Obtain information about an IMAP folder
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to obtain information about a mailbox
 * folder using libfetch's IMAP capabilities via the EXAMINE command.
 *
 * Note that this example requires libfetch 7.30.0 or above.
 */

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if (fetch)
  {
    /* Set username and password */
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "secret");

    /* This is just the server URL */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://imap.example.com");

    /* Set the EXAMINE command specifying the mailbox folder */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "EXAMINE OUTBOX");

    /* Perform the custom request */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* Always cleanup */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
