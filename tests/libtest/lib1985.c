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

/* URL1, URL2, port, address */

static CURLcode test_lib1985(const char *URL)
{
  char host1[80];
  char host2[80];
  CURL *curl = NULL;
  struct curl_slist *slist = NULL;
  struct curl_slist *slist2 = NULL;
  CURLcode r1 = CURLE_OK, r2 = CURLE_OK;
  curl_global_init(CURL_GLOBAL_ALL);

  curl_msnprintf(host1, sizeof(host1), "firsthost:%s:%s",
                 libtest_arg3, libtest_arg4);
  curl_msnprintf(host2, sizeof(host2), "secondhost:%s:%s",
                 libtest_arg3, libtest_arg4);
  slist = curl_slist_append(slist, host1);
  if(!slist)
    goto error;
  slist2 = curl_slist_append(slist, host2);
  if(!slist2)
    goto error;
  slist = slist2;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_RESOLVE, slist);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);

    curl_easy_setopt(curl, CURLOPT_USERPWD,
                     "alice:correct-horse-battery-staple");
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, "unused-token");
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH,
                     (long)(CURLAUTH_BASIC | CURLAUTH_BEARER));
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    r1 = curl_easy_perform(curl);
    curl_mprintf("STEP1_CODE=%d\n", (int)r1);

    /* Step 2: reuse handle for HostB with Digest stale state leaks */
    curl_easy_setopt(curl, CURLOPT_URL, libtest_arg2);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_DIGEST);
    r2 = curl_easy_perform(curl);
    curl_mprintf("STEP2_CODE=%d\n", (int)r2);
  }

error:
  curl_easy_cleanup(curl);
  curl_slist_free_all(slist);
  curl_global_cleanup();
  return r2;
}
