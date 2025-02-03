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
 * Modify the properties of an email over IMAP
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to modify an existing mail using
 * libfetch's IMAP capabilities with the STORE command.
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

    /* This is the mailbox folder to select */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://imap.example.com/INBOX");

    /* Set the STORE command with the Deleted flag for message 1. Note that
     * you can use the STORE command to set other flags such as Seen, Answered,
     * Flagged, Draft and Recent. */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "STORE 1 +Flags \\Deleted");

    /* Perform the custom request */
    res = fetch_easy_perform(fetch);

    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));
    else
    {
      /* Set the EXPUNGE command, although you can use the CLOSE command if you
       * do not want to know the result of the STORE */
      fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "EXPUNGE");

      /* Perform the second custom request */
      res = fetch_easy_perform(fetch);

      /* Check for errors */
      if (res != FETCHE_OK)
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));
    }

    /* Always cleanup */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
