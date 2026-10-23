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

/* An option libcurl knows about, but which is left out of the build because
   its feature is disabled, must make curl_easy_setopt() return
   CURLE_NOT_BUILT_IN. Only an option libcurl does not know at all may return
   CURLE_UNKNOWN_OPTION. Setting every known option works for any build
   configuration. */
static CURLcode test_lib1923(const char *URL)
{
  const struct curl_easyoption *o;
  int error = 0;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);

  for(o = curl_easy_option_next(NULL); o; o = curl_easy_option_next(o)) {
    CURLcode result;
    CURL *curl;

    if(o->flags & CURLOT_FLAG_ALIAS)
      continue;

    curl = curl_easy_init();
    if(!curl) {
      curl_global_cleanup();
      return TEST_ERR_EASY_INIT;
    }

    switch(o->type) {
    case CURLOT_LONG:
    case CURLOT_VALUES:
      result = curl_easy_setopt(curl, o->id, 0L);
      break;
    case CURLOT_OFF_T:
      result = curl_easy_setopt(curl, o->id, (curl_off_t)0);
      break;
    default:
      result = curl_easy_setopt(curl, o->id, (void *)NULL);
      break;
    }

    if(result == CURLE_UNKNOWN_OPTION) {
      curl_mfprintf(stderr, "curl_easy_setopt(%s...) returned %d\n",
                    o->name, (int)result);
      error++;
    }
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();
  return error == 0 ? CURLE_OK : TEST_ERR_FAILURE;
}
