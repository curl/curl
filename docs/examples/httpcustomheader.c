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
 * HTTP request with custom modified, removed and added headers
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_slist *chunk = NULL;

    /* Remove a header fetch would otherwise add by itself */
    chunk = fetch_slist_append(chunk, "Accept:");

    /* Add a custom header */
    chunk = fetch_slist_append(chunk, "Another: yes");

    /* Modify a header fetch otherwise adds differently */
    chunk = fetch_slist_append(chunk, "Host: example.com");

    /* Add a header with "blank" contents to the right of the colon. Note that
       we are then using a semicolon in the string we pass to fetch! */
    chunk = fetch_slist_append(chunk, "X-silly-header;");

    /* set our custom set of headers */
    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, chunk);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "localhost");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);

    /* free the custom headers */
    fetch_slist_free_all(chunk);
  }
  return 0;
}
