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

#define FIRSTHOST "first.test"
#define SECONDHOST "second.test"

static CURLcode test_lib1686(const char *hostip)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  const char *httpport = libtest_arg2;
  char firsturl[100];
  char secondurl[100];
  char firstres[100];
  char secondres[100];
  struct curl_slist *host = NULL;
  struct curl_slist *host2 = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* create strings for CURLOPT_RESOLVE */
  curl_msnprintf(firstres, sizeof(firstres), "%s:%s:%s",
                 FIRSTHOST, httpport, hostip);
  curl_msnprintf(secondres, sizeof(secondres), "%s:%s:%s",
                 SECONDHOST, httpport, hostip);

  /* create URLs */
  curl_msnprintf(firsturl, sizeof(firsturl), "http://%s:%s/api",
                 FIRSTHOST, httpport);
  curl_msnprintf(secondurl, sizeof(secondurl), "http://%s:%s/hook",
                 SECONDHOST, httpport);

  host = curl_slist_append(NULL, firstres);
  if(!host)
    goto test_cleanup;
  host2 = curl_slist_append(host, secondres);
  if(!host2)
    goto test_cleanup;
  host = host2;

  curl = curl_easy_init();
  if(curl) {
    easy_setopt(curl, CURLOPT_RESOLVE, host);
    easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
    easy_setopt(curl, CURLOPT_USERPWD, "alice:bond");
    easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);

    easy_setopt(curl, CURLOPT_URL, firsturl);
    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;

    easy_setopt(curl, CURLOPT_URL, secondurl);
    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;

    easy_setopt(curl, CURLOPT_USERPWD, "bob:secret");
    easy_setopt(curl, CURLOPT_URL, secondurl);
    result = curl_easy_perform(curl);
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  curl_slist_free_all(host);
  return result;
}
