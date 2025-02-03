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
 * Extract lots of TLS certificate info.
 * </DESC>
 */
#include <stdio.h>

#include <fetch/fetch.h>

static size_t wrfu(void *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)stream;
  (void)ptr;
  return size * nmemb;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/");

    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, wrfu);

    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 0L);
    fetch_easy_setopt(fetch, FETCHOPT_CERTINFO, 1L);

    res = fetch_easy_perform(fetch);

    if (!res)
    {
      struct fetch_certinfo *certinfo;

      res = fetch_easy_getinfo(fetch, FETCHINFO_CERTINFO, &certinfo);

      if (!res && certinfo)
      {
        int i;

        printf("%d certs!\n", certinfo->num_of_certs);

        for (i = 0; i < certinfo->num_of_certs; i++)
        {
          struct fetch_slist *slist;

          for (slist = certinfo->certinfo[i]; slist; slist = slist->next)
            printf("%s\n", slist->data);
        }
      }
    }

    fetch_easy_cleanup(fetch);
  }

  fetch_global_cleanup();

  return 0;
}
