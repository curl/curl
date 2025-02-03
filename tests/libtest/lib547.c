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
/* argv1 = URL
 * argv2 = proxy
 * argv3 = proxyuser:password
 */

#include "test.h"

#include "memdebug.h"

#define UPLOADTHIS "this is the blurb we want to upload\n"

#ifndef LIB548
static size_t readcallback(char *ptr,
                           size_t size,
                           size_t nmemb,
                           void *clientp)
{
  int *counter = (int *)clientp;

  if (*counter)
  {
    /* only do this once and then require a clearing of this */
    fprintf(stderr, "READ ALREADY DONE!\n");
    return 0;
  }
  (*counter)++; /* bump */

  if (size * nmemb >= strlen(UPLOADTHIS))
  {
    fprintf(stderr, "READ!\n");
    strcpy(ptr, UPLOADTHIS);
    return strlen(UPLOADTHIS);
  }
  fprintf(stderr, "READ NOT FINE!\n");
  return 0;
}
static fetchioerr ioctlcallback(FETCH *handle,
                                int cmd,
                                void *clientp)
{
  int *counter = (int *)clientp;
  (void)handle; /* unused */
  if (cmd == FETCHIOCMD_RESTARTREAD)
  {
    fprintf(stderr, "REWIND!\n");
    *counter = 0; /* clear counter to make the read callback restart */
  }
  return FETCHIOE_OK;
}

#endif

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
#ifndef LIB548
  int counter = 0;
#endif

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
#ifdef LIB548
  /* set the data to POST with a mere pointer to a null-terminated string */
  test_setopt(fetch, FETCHOPT_POSTFIELDS, UPLOADTHIS);
#else
  /* 547 style, which means reading the POST data from a callback */
  FETCH_IGNORE_DEPRECATION(
      test_setopt(fetch, FETCHOPT_IOCTLFUNCTION, ioctlcallback);
      test_setopt(fetch, FETCHOPT_IOCTLDATA, &counter);)
  test_setopt(fetch, FETCHOPT_READFUNCTION, readcallback);
  test_setopt(fetch, FETCHOPT_READDATA, &counter);
  /* We CANNOT do the POST fine without setting the size (or choose
     chunked)! */
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)strlen(UPLOADTHIS));
#endif
  test_setopt(fetch, FETCHOPT_POST, 1L);
  test_setopt(fetch, FETCHOPT_PROXY, libtest_arg2);
  test_setopt(fetch, FETCHOPT_PROXYUSERPWD, libtest_arg3);
  test_setopt(fetch, FETCHOPT_PROXYAUTH,
              (long)(FETCHAUTH_NTLM | FETCHAUTH_DIGEST | FETCHAUTH_BASIC));

  res = fetch_easy_perform(fetch);

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
