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

/* every option libcurl knows about is either supported by this build or
   reported as not built in, never as unknown */
static CURLcode test_lib1924(const char *URL)
{
  const struct curl_easyoption *o;
  CURLcode result = CURLE_OK;
  (void)URL;

  global_init(CURL_GLOBAL_ALL);

  for(o = curl_easy_option_next(NULL); o; o = curl_easy_option_next(o)) {
    CURL *curl;
    CURLcode rc;

    if(o->flags & CURLOT_FLAG_ALIAS)
      continue;

    curl = curl_easy_init();
    if(!curl) {
      result = TEST_ERR_EASY_INIT;
      break;
    }

    switch(o->type) {
    case CURLOT_LONG:
    case CURLOT_VALUES:
      rc = curl_easy_setopt(curl, o->id, 0L);
      break;
    case CURLOT_OFF_T:
      rc = curl_easy_setopt(curl, o->id, (curl_off_t)0);
      break;
    default:
      rc = curl_easy_setopt(curl, o->id, NULL);
      break;
    }

    if(rc == CURLE_UNKNOWN_OPTION) {
      curl_mprintf("CURLOPT_%s returned CURLE_UNKNOWN_OPTION\n", o->name);
      result = TEST_ERR_FAILURE;
    }

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return result;
}
