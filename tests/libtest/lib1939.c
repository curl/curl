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

static CURLcode test_lib1939(const char *URL)
{
  CURLM *multi;
  CURL *curl;
  int running_handles;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  multi = curl_multi_init();
  if(multi) {
    curl = curl_easy_init();
    if(curl) {
      CURLcode result;
      CURLMcode mresult;

      /* Crash only happens when using HTTPS */
      result = curl_easy_setopt(curl, CURLOPT_URL, URL);
      if(!result)
        /* Any old HTTP tunneling proxy will do here */
        result = curl_easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);

      if(!result) {

        /* We are going to drive the transfer using multi interface here,
           because we want to stop during the middle. */
        mresult = curl_multi_add_handle(multi, curl);

        if(!mresult)
          /* Run the multi handle once, just enough to start establishing an
             HTTPS connection. */
          mresult = curl_multi_perform(multi, &running_handles);

        if(mresult)
          curl_mfprintf(stderr, "curl_multi_perform failed\n");
      }
      /* Close the easy handle *before* the multi handle. Doing it the other
         way around avoids the issue. */
      curl_easy_cleanup(curl);
    }
    curl_multi_cleanup(multi); /* double-free happens here */
  }
  curl_global_cleanup();
  return CURLE_OK;
}
