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
#include "test.h"

#include "memdebug.h"

/* Test case code based on source in a bug report filed by James Bursa on
   28 Apr 2004 */

FETCHcode test(char *URL)
{
  FETCHcode code;
  int rc = 99;

  code = fetch_global_init(FETCH_GLOBAL_ALL);
  if (code == FETCHE_OK)
  {
    FETCH *fetch = fetch_easy_init();
    if (fetch)
    {
      FETCH *fetch2;

      fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
      fetch_easy_setopt(fetch, FETCHOPT_HEADER, 1L);

      fetch2 = fetch_easy_duphandle(fetch);
      if (fetch2)
      {

        code = fetch_easy_setopt(fetch2, FETCHOPT_URL, URL);
        if (code == FETCHE_OK)
        {

          code = fetch_easy_perform(fetch2);
          if (code == FETCHE_OK)
            rc = 0;
          else
            rc = 1;
        }
        else
          rc = 2;

        fetch_easy_cleanup(fetch2);
      }
      else
        rc = 3;

      fetch_easy_cleanup(fetch);
    }
    else
      rc = 4;

    fetch_global_cleanup();
  }
  else
    rc = 5;

  return (FETCHcode)rc;
}
