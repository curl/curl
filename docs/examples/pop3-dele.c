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
 * Delete POP3 emails
 * </DESC>
 */

#include <stdio.h>
#include <fetch/fetch.h>

/* This is a simple example showing how to delete an existing mail using
 * libfetch's POP3 capabilities.
 *
 * Note that this example requires libfetch 7.26.0 or above.
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

    /* You can specify the message either in the URL or DELE command */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "pop3://pop.example.com/1");

    /* Set the DELE command */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "DELE");

    /* Do not perform a transfer as DELE returns no data */
    fetch_easy_setopt(fetch, FETCHOPT_NOBODY, 1L);

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
