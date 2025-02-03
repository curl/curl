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
 * Set working URL with FETCHU *.
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

#if !FETCH_AT_LEAST_VERSION(7, 80, 0)
#error "this example requires fetch 7.80.0 or later"
#endif

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  FETCHU *urlp;
  FETCHUcode uc;

  /* get a fetch handle */
  fetch = fetch_easy_init();

  /* init Fetch URL */
  urlp = fetch_url();
  uc = fetch_url_set(urlp, FETCHUPART_URL,
                     "http://example.com/path/index.html", 0);

  if (uc)
  {
    fprintf(stderr, "fetch_url_set() failed: %s", fetch_url_strerror(uc));
    goto cleanup;
  }

  if (fetch)
  {
    /* set urlp to use as working URL */
    fetch_easy_setopt(fetch, FETCHOPT_FETCHU, urlp);
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* only allow HTTP, TFTP and SFTP */
    fetch_easy_setopt(fetch, FETCHOPT_PROTOCOLS_STR, "http,tftp,sftp");

    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    goto cleanup;
  }

cleanup:
  fetch_url_cleanup(urlp);
  fetch_easy_cleanup(fetch);
  return 0;
}
