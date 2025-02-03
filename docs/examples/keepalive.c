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
 * Use the TCP keep-alive options
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
    /* enable TCP keep-alive for this transfer */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPALIVE, 1L);

    /* keep-alive idle time to 120 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPIDLE, 120L);

    /* interval time between keep-alive probes: 60 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPINTVL, 60L);

    /* maximum number of keep-alive probes: 3 */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPCNT, 3L);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://curl.se/");

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }

  return (int)res;
}
