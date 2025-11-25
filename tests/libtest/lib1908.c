/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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

static CURLcode test_lib1908(const char *URL)
{
  CURLcode res = TEST_ERR_MAJOR_BAD;
  CURL *curl;
  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_ALTSVC, libtest_arg2);
    res = curl_easy_perform(curl);

    if(!res) {
      /* make a copy and check that this also has alt-svc activated */
      CURL *curldupe = curl_easy_duphandle(curl);
      if(curldupe) {
        res = curl_easy_perform(curldupe);
        /* we close the second handle first, which makes it store the alt-svc
           file only to get overwritten when the next handle is closed! */
        curl_easy_cleanup(curldupe);
      }
    }

    curl_easy_reset(curl);

    /* using the same filename for the alt-svc cache, this clobbers the
       content just written from the 'curldupe' handle */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;
}
