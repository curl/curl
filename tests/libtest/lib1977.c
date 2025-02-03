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

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCHU *fetchu = fetch_url();
  FETCHU *fetchu_2 = fetch_url();
  FETCH *fetch;
  char *effective = NULL;

  global_init(FETCH_GLOBAL_ALL);
  easy_init(fetch);

  /* first transfer: set just the URL in the first FETCHU handle */
  fetch_url_set(fetchu, FETCHUPART_URL, URL, FETCHU_DEFAULT_SCHEME);
  easy_setopt(fetch, FETCHOPT_FETCHU, fetchu);

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  printf("effective URL: %s\n", effective);


  /* second transfer: set URL + query in the second FETCHU handle */
  fetch_url_set(fetchu_2, FETCHUPART_URL, URL, FETCHU_DEFAULT_SCHEME);
  fetch_url_set(fetchu_2, FETCHUPART_QUERY, "foo", 0);
  easy_setopt(fetch, FETCHOPT_FETCHU, fetchu_2);

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  printf("effective URL: %s\n", effective);


  /* third transfer: append extra query in the second FETCHU handle, but do not
     set FETCHOPT_FETCHU again. this is to test that the contents of the handle
     is allowed to change between transfers and is used without having to set
     FETCHOPT_FETCHU again */
  fetch_url_set(fetchu_2, FETCHUPART_QUERY, "bar", FETCHU_APPENDQUERY);

  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  effective = NULL;
  res = fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_URL, &effective);
  if(res)
    goto test_cleanup;
  printf("effective URL: %s\n", effective);


test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_url_cleanup(fetchu);
  fetch_url_cleanup(fetchu_2);
  fetch_global_cleanup();

  return res;
}
