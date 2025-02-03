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
 * Retrieve emails from a shared IMAP mailbox
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to fetch mail using libfetch's IMAP
 * capabilities.
 *
 * Note that this example requires libfetch 7.66.0 or above.
 */

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if (fetch)
  {
    /* Set the username and password */
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "secret");

    /* Set the authorization identity (identity to act as) */
    fetch_easy_setopt(fetch, FETCHOPT_SASL_AUTHZID, "shared-mailbox");

    /* Force PLAIN authentication */
    fetch_easy_setopt(fetch, FETCHOPT_LOGIN_OPTIONS, "AUTH=PLAIN");

    /* This fetches message 1 from the user's inbox */
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                      "imap://imap.example.com/INBOX/;UID=1");

    /* Perform the fetch */
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
