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

/* argv[1]: ws URL, argv[2-3]: extension request headers (or '-').
 * In raw mode, curl does not interpret extension-specific WebSocket frames. */
static CURLcode test_cli_ws_raw_extensions(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURL *curl;
  CURLcode result;
  struct curl_slist *headers = NULL;

  if(!URL || !libtest_arg2)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  if(strcmp(libtest_arg2, "-")) {
    headers = curl_slist_append(NULL, libtest_arg2);
    if(!headers) {
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return CURLE_OUT_OF_MEMORY;
    }
  }
  if(libtest_arg3 && strcmp(libtest_arg3, "-")) {
    struct curl_slist *next = curl_slist_append(headers, libtest_arg3);
    if(!next) {
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return CURLE_OUT_OF_MEMORY;
    }
    headers = next;
  }
  if(headers)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_WS_OPTIONS, CURLWS_RAW_MODE);
  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
  result = curl_easy_perform(curl);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return result;
#else
  (void)URL;
  return CURLE_UNSUPPORTED_PROTOCOL;
#endif
}
