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
 * Access HTTP server over Unix domain socket
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

#ifdef USE_ABSTRACT
/*
 * The abstract socket namespace is a nonportable Linux extension. The name
 * has no connection with filesystem pathnames.
 */
#define ABSTRACT "http-unix-domain"
#else
#define PATH "/tmp/http-unix-domain"
#endif

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://example.com");

#ifdef USE_ABSTRACT
    fetch_easy_setopt(fetch, FETCHOPT_ABSTRACT_UNIX_SOCKET, ABSTRACT);
#else
    fetch_easy_setopt(fetch, FETCHOPT_UNIX_SOCKET_PATH, PATH);
#endif

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
