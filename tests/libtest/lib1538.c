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

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCHcode easyret;
  FETCHMcode multiret;
  FETCHSHcode shareret;
  FETCHUcode urlret;
  (void)URL;

  fetch_easy_strerror((FETCHcode)INT_MAX);
  fetch_multi_strerror((FETCHMcode)INT_MAX);
  fetch_share_strerror((FETCHSHcode)INT_MAX);
  fetch_url_strerror((FETCHUcode)INT_MAX);
  fetch_easy_strerror((FETCHcode)-INT_MAX);
  fetch_multi_strerror((FETCHMcode)-INT_MAX);
  fetch_share_strerror((FETCHSHcode)-INT_MAX);
  fetch_url_strerror((FETCHUcode)-INT_MAX);
  for (easyret = FETCHE_OK; easyret <= FETCH_LAST; easyret++)
  {
    printf("e%d: %s\n", (int)easyret, fetch_easy_strerror(easyret));
  }
  for (multiret = FETCHM_CALL_MULTI_PERFORM; multiret <= FETCHM_LAST;
       multiret++)
  {
    printf("m%d: %s\n", (int)multiret, fetch_multi_strerror(multiret));
  }
  for (shareret = FETCHSHE_OK; shareret <= FETCHSHE_LAST; shareret++)
  {
    printf("s%d: %s\n", (int)shareret, fetch_share_strerror(shareret));
  }
  for (urlret = FETCHUE_OK; urlret <= FETCHUE_LAST; urlret++)
  {
    printf("u%d: %s\n", (int)urlret, fetch_url_strerror(urlret));
  }

  return res;
}
