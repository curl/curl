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
 * argv2 = main auth type
 * argv3 = second auth type
 */

#include "test.h"
#include "memdebug.h"

static FETCHcode send_request(FETCH *fetch, const char *url, int seq,
                              long auth_scheme, const char *userpwd)
{
  FETCHcode res;
  size_t len = strlen(url) + 4 + 1;
  char *full_url = malloc(len);
  if (!full_url)
  {
    fprintf(stderr, "Not enough memory for full url\n");
    return FETCHE_OUT_OF_MEMORY;
  }

  msnprintf(full_url, len, "%s%04d", url, seq);
  fprintf(stderr, "Sending new request %d to %s with credential %s "
                  "(auth %ld)\n",
          seq, full_url, userpwd, auth_scheme);
  test_setopt(fetch, FETCHOPT_URL, full_url);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_HTTPGET, 1L);
  test_setopt(fetch, FETCHOPT_USERPWD, userpwd);
  test_setopt(fetch, FETCHOPT_HTTPAUTH, auth_scheme);

  res = fetch_easy_perform(fetch);

test_cleanup:
  free(full_url);
  return res;
}

static FETCHcode send_wrong_password(FETCH *fetch, const char *url, int seq,
                                     long auth_scheme)
{
  return send_request(fetch, url, seq, auth_scheme, "testuser:wrongpass");
}

static FETCHcode send_right_password(FETCH *fetch, const char *url, int seq,
                                     long auth_scheme)
{
  return send_request(fetch, url, seq, auth_scheme, "testuser:testpass");
}

static long parse_auth_name(const char *arg)
{
  if (!arg)
    return FETCHAUTH_NONE;
  if (fetch_strequal(arg, "basic"))
    return FETCHAUTH_BASIC;
  if (fetch_strequal(arg, "digest"))
    return FETCHAUTH_DIGEST;
  if (fetch_strequal(arg, "ntlm"))
    return FETCHAUTH_NTLM;
  return FETCHAUTH_NONE;
}

FETCHcode test(char *url)
{
  FETCHcode res;
  FETCH *fetch = NULL;

  long main_auth_scheme = parse_auth_name(libtest_arg2);
  long fallback_auth_scheme = parse_auth_name(libtest_arg3);

  if (main_auth_scheme == FETCHAUTH_NONE ||
      fallback_auth_scheme == FETCHAUTH_NONE)
  {
    fprintf(stderr, "auth schemes not found on commandline\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* Send wrong password, then right password */

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  res = send_wrong_password(fetch, url, 100, main_auth_scheme);
  if (res != FETCHE_OK)
    goto test_cleanup;

  res = send_right_password(fetch, url, 200, fallback_auth_scheme);
  if (res != FETCHE_OK)
    goto test_cleanup;

  fetch_easy_cleanup(fetch);

  /* Send wrong password twice, then right password */
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  res = send_wrong_password(fetch, url, 300, main_auth_scheme);
  if (res != FETCHE_OK)
    goto test_cleanup;

  res = send_wrong_password(fetch, url, 400, fallback_auth_scheme);
  if (res != FETCHE_OK)
    goto test_cleanup;

  res = send_right_password(fetch, url, 500, fallback_auth_scheme);
  if (res != FETCHE_OK)
    goto test_cleanup;

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
