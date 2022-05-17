/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include "test.h"

#include "memdebug.h"

int test(char *URL)
{
  CURLM *multi;
  CURL *easy;
  int running_handles;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  multi = curl_multi_init();
  if(multi) {
    easy = curl_easy_init();
    if(easy) {
      CURLcode c;
      CURLMcode m;

      /* Crash only happens when using HTTPS */
      c = curl_easy_setopt(easy, CURLOPT_URL, URL);
      if(!c)
        /* Any old HTTP tunneling proxy will do here */
        c = curl_easy_setopt(easy, CURLOPT_PROXY, libtest_arg2);

      if(!c) {

        /* We're going to drive the transfer using multi interface here,
           because we want to stop during the middle. */
        m = curl_multi_add_handle(multi, easy);

        if(!m)
          /* Run the multi handle once, just enough to start establishing an
             HTTPS connection. */
          m = curl_multi_perform(multi, &running_handles);

        if(m)
          fprintf(stderr, "curl_multi_perform failed\n");
      }
      /* Close the easy handle *before* the multi handle. Doing it the other
         way around avoids the issue. */
      curl_easy_cleanup(easy);
    }
    curl_multi_cleanup(multi); /* double-free happens here */
  }
  curl_global_cleanup();
  return CURLE_OK;
}
