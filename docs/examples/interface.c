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
 * Use FETCHOPT_INTERFACE to bind the outgoing socket to an interface
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

int main(void)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  fetch = fetch_easy_init();
  if (fetch)
  {
    /* The interface needs to be a local existing interface over which you can
       connect to the host in the URL. It can also specify an IP address, but
       that address needs to be assigned one of the local network
       interfaces. */
    fetch_easy_setopt(fetch, FETCHOPT_INTERFACE, "enp3s0");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://fetch.se/");

    res = fetch_easy_perform(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
