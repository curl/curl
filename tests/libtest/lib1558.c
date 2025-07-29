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
#include "first.h"

#include "memdebug.h"

static CURLcode test_lib1558(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  long protocol = 0;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  res = curl_easy_perform(curl);
  if(res) {
    curl_mfprintf(stderr, "curl_easy_perform() returned %d (%s)\n",
                  res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  res = curl_easy_getinfo(curl, CURLINFO_PROTOCOL, &protocol);
  if(res) {
    curl_mfprintf(stderr, "curl_easy_getinfo() returned %d (%s)\n",
                  res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  curl_mprintf("Protocol: %lx\n", protocol);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return CURLE_OK;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res; /* return the final return code */
}
