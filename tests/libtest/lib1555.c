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
/*
 * Verify that some API functions are locked from being called inside callback
 */

#include "test.h"

#include "memdebug.h"

static FETCH *fetch;

static int progressCallback(void *arg,
                            double dltotal,
                            double dlnow,
                            double ultotal,
                            double ulnow)
{
  FETCHcode res = FETCHE_OK;
  char buffer[256];
  size_t n = 0;
  (void)arg;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  res = fetch_easy_recv(fetch, buffer, 256, &n);
  printf("fetch_easy_recv returned %d\n", res);
  res = fetch_easy_send(fetch, buffer, n, &n);
  printf("fetch_easy_send returned %d\n", res);

  return 1;
}

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_TIMEOUT, (long)7);
  easy_setopt(fetch, FETCHOPT_NOSIGNAL, (long)1);
  FETCH_IGNORE_DEPRECATION(
      easy_setopt(fetch, FETCHOPT_PROGRESSFUNCTION, progressCallback);
      easy_setopt(fetch, FETCHOPT_PROGRESSDATA, NULL);)
  easy_setopt(fetch, FETCHOPT_NOPROGRESS, (long)0);

  res = fetch_easy_perform(fetch);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
