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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHcode ret = FETCHE_OK;
  FETCH *hnd;
  start_test_timing();

  fetch_global_init(FETCH_GLOBAL_ALL);

  hnd = fetch_easy_init();
  if (hnd)
  {
    fetch_easy_setopt(hnd, FETCHOPT_URL, URL);
    fetch_easy_setopt(hnd, FETCHOPT_FILETIME, 1L);
    ret = fetch_easy_perform(hnd);
    if (FETCHE_OK == ret)
    {
      long filetime;
      ret = fetch_easy_getinfo(hnd, FETCHINFO_FILETIME, &filetime);
      /* MTDM fails with 550, so filetime should be -1 */
      if ((FETCHE_OK == ret) && (filetime != -1))
      {
        /* we just need to return something which is not FETCHE_OK */
        ret = FETCHE_UNSUPPORTED_PROTOCOL;
      }
    }
    fetch_easy_cleanup(hnd);
  }
  fetch_global_cleanup();
  return ret;
}
