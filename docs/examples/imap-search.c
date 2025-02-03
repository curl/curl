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
 * Search for new IMAP emails
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to search for new messages using
 * libfetch's IMAP capabilities.
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

    /* This is mailbox folder to select */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://imap.example.com/INBOX");

    /* Set the SEARCH command specifying what we want to search for. Note that
     * this can contain a message sequence set and a number of search criteria
     * keywords including flags such as ANSWERED, DELETED, DRAFT, FLAGGED, NEW,
     * RECENT and SEEN. For more information about the search criteria please
     * see RFC-3501 section 6.4.4.   */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "SEARCH NEW");

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
