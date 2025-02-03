/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) James Fuller, <jim@webcomposite.com>, et al.
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
 * Set maximum number of persistent connections to 1.
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if (fetch)
  {
    const char *urls[] = {
        "https://example.com",
        "https://curl.se",
        "https://www.example/",
        NULL /* end of list */
    };
    int i = 0;

    /* Change the maximum number of persistent connection   */
    fetch_easy_setopt(fetch, FETCHOPT_MAXCONNECTS, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* loop over the URLs */
    while (urls[i])
    {
      fetch_easy_setopt(fetch, FETCHOPT_URL, urls[i]);

      /* Perform the request, res gets the return code */
      res = fetch_easy_perform(fetch);
      /* Check for errors */
      if (res != FETCHE_OK)
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));
      i++;
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
