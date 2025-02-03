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
 * HTTP PUT using FETCHOPT_POSTFIELDS
 * </DESC>
 */
#include <stdio.h>
#include <fcntl.h>
#include <fetch/fetch.h>

static const char olivertwist[] =
    "Among other public buildings in a certain town, which for many reasons "
    "it will be prudent to refrain from mentioning, and to which I will assign "
    "no fictitious name, there is one anciently common to most towns, great or "
    "small: to wit, a workhouse; and in this workhouse was born; on a day and "
    "date which I need not trouble myself to repeat, inasmuch as it can be of "
    "no possible consequence to the reader, in this stage of the business at "
    "all events; the item of mortality whose name is prefixed";

/* ... to the head of this chapter. String cut off to stick within the C90
   509 byte limit. */

/*
 * This example shows an HTTP PUT operation that sends a fixed buffer with
 * FETCHOPT_POSTFIELDS to the URL given as an argument.
 */

int main(int argc, char **argv)
{
  FETCH *fetch;
  FETCHcode res;
  char *url;

  if (argc < 2)
    return 1;

  url = argv[1];

  /* In Windows, this inits the Winsock stuff */
  fetch_global_init(FETCH_GLOBAL_ALL);

  /* get a fetch handle */
  fetch = fetch_easy_init();
  if (fetch)
  {
    struct fetch_slist *headers = NULL;

    /* default type with postfields is application/x-www-form-urlencoded,
       change it if you want */
    headers = fetch_slist_append(headers, "Content-Type: literature/classic");
    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headers);

    /* pass on content in request body. When FETCHOPT_POSTFIELDSIZE is not used,
       fetch does strlen to get the size. */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, olivertwist);

    /* override the POST implied by FETCHOPT_POSTFIELDS
     *
     * Warning: FETCHOPT_CUSTOMREQUEST is problematic, especially if you want
     * to follow redirects. Be aware.
     */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "PUT");

    /* specify target URL, and note that this URL should include a file
       name, not only a directory */
    fetch_easy_setopt(fetch, FETCHOPT_URL, url);

    /* Now run off and do what you have been told! */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);

    /* free headers */
    fetch_slist_free_all(headers);
  }

  fetch_global_cleanup();
  return 0;
}
