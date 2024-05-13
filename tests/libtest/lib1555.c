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
 * Verify that some API functions are locked from being called inside callback
 */

#include "test.h"

#include "memdebug.h"

static CURL *curl;

static int progressCallback(void *arg,
                            double dltotal,
                            double dlnow,
                            double ultotal,
                            double ulnow)
{
  CURLcode res = CURLE_OK;
  char buffer[256];
  size_t n = 0;
  (void)arg;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  res = curl_easy_recv(curl, buffer, 256, &n);
  printf("curl_easy_recv returned %d\n", res);
  res = curl_easy_send(curl, buffer, n, &n);
  printf("curl_easy_send returned %d\n", res);

  return 1;
}

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_TIMEOUT, (long)7);
  easy_setopt(curl, CURLOPT_NOSIGNAL, (long)1);
  CURL_IGNORE_DEPRECATION(
    easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progressCallback);
    easy_setopt(curl, CURLOPT_PROGRESSDATA, NULL);
  )
  easy_setopt(curl, CURLOPT_NOPROGRESS, (long)0);

  res = curl_easy_perform(curl);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
