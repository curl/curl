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

#include "memdebug.h"

/* Test inspired by github issue 3340 */

static size_t writecb(char *buffer, size_t size, size_t nitems,
                      void *outstream)
{
  (void)buffer;
  (void)size;
  (void)nitems;
  (void)outstream;
  return 0;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  long fetchResponseCode;
  long fetchRedirectCount;
  char *effectiveUrl = NULL;
  char *redirectUrl = NULL;
#ifdef LIB1543
  FETCHU *urlu = NULL;
#endif
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
#ifdef LIB1543
  /* set FETCHOPT_URLU */
  {
    FETCHUcode rc = FETCHUE_OK;
    urlu = fetch_url();
    if (urlu)
      rc = fetch_url_set(urlu, FETCHUPART_URL, URL, FETCHU_ALLOW_SPACE);
    if (!urlu || rc)
    {
      goto test_cleanup;
    }
    test_setopt(fetch, FETCHOPT_FETCHU, urlu);
  }
  test_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
#else
  test_setopt(fetch, FETCHOPT_URL, URL);
  /* just to make it explicit and visible in this test: */
  test_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 0L);
#endif

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);

  fetch_easy_getinfo(fetch, FETCHINFO_RESPONSE_CODE, &fetchResponseCode);
  fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_COUNT, &fetchRedirectCount);
  fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_URL, &effectiveUrl);
  fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_URL, &redirectUrl);
  test_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);

  printf("res %d\n"
         "status %ld\n"
         "redirects %ld\n"
         "effectiveurl %s\n"
         "redirecturl %s\n",
         res,
         fetchResponseCode,
         fetchRedirectCount,
         effectiveUrl,
         redirectUrl ? redirectUrl : "blank");

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
#ifdef LIB1543
  fetch_url_cleanup(urlu);
#endif
  return res;
}
