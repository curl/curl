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
 * Extract headers post transfer with the header API
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

static size_t write_cb(char *data, size_t n, size_t l, void *userp)
{
  /* take care of the data here, ignored in this example */
  (void)data;
  (void)userp;
  return n * l;
}

int main(void)
{
  FETCH *fetch;

  fetch = fetch_easy_init();
  if (fetch)
  {
    FETCHcode res;
    struct fetch_header *header;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    /* example.com is redirected, so we tell libfetch to follow redirection */
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

    /* this example just ignores the content */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_cb);

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    if (FETCHHE_OK == fetch_easy_header(fetch, "Content-Type", 0, FETCHH_HEADER,
                                        -1, &header))
      printf("Got content-type: %s\n", header->value);

    printf("All server headers:\n");
    {
      struct fetch_header *h;
      struct fetch_header *prev = NULL;
      do
      {
        h = fetch_easy_nextheader(fetch, FETCHH_HEADER, -1, prev);
        if (h)
          printf(" %s: %s (%u)\n", h->name, h->value, (int)h->amount);
        prev = h;
      } while (h);
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
