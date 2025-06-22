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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/*
 * Test case converted from bug report #1318 by Petr Novak.
 *
 * Before the fix, this test program returned 52 (CURLE_GOT_NOTHING) instead
 * of 42 (CURLE_ABORTED_BY_CALLBACK).
 */

#include "first.h"

#include "memdebug.h"

static int progressKiller(void *arg,
                          double dltotal,
                          double dlnow,
                          double ultotal,
                          double ulnow)
{
  (void)arg;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  curl_mprintf("PROGRESSFUNCTION called\n");
  return 1;
}

static CURLcode test_lib1513(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_TIMEOUT, (long)7);
  easy_setopt(curl, CURLOPT_NOSIGNAL, (long)1);
  easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progressKiller);
  easy_setopt(curl, CURLOPT_PROGRESSDATA, NULL);
  easy_setopt(curl, CURLOPT_NOPROGRESS, (long)0);

  res = curl_easy_perform(curl);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
