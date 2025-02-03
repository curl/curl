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

/*
  Based on a bug report recipe by Rene Bernhardt in
  https://fetch.se/mail/lib-2011-10/0323.html

  It is reproducible by the following steps:

  - Use a proxy that offers NTLM and Negotiate ( FETCHOPT_PROXY and
  FETCHOPT_PROXYPORT)
  - Tell libfetch NOT to use Negotiate  FETCH_EASY_SETOPT(FETCHOPT_PROXYAUTH,
  FETCHAUTH_BASIC | FETCHAUTH_DIGEST | FETCHAUTH_NTLM)
  - Start the request
*/

#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  long usedauth = 0;

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_PROXYAUTH,
              (long) (FETCHAUTH_BASIC | FETCHAUTH_DIGEST | FETCHAUTH_NTLM));
  test_setopt(fetch, FETCHOPT_PROXY, libtest_arg2); /* set in first.c */
  test_setopt(fetch, FETCHOPT_PROXYUSERPWD, "me:password");

  res = fetch_easy_perform(fetch);

  res = fetch_easy_getinfo(fetch, FETCHINFO_PROXYAUTH_USED, &usedauth);
  if(FETCHAUTH_NTLM != usedauth) {
    printf("FETCHINFO_PROXYAUTH_USED did not say NTLM\n");
  }

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
