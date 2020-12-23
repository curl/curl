/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2020, Linus Nielsen Feltzing, <linus@haxx.se>
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
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

int test(char *URL)
{
  CURLcode ret = CURLE_OK;
  CURL *hnd;
  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  hnd = curl_easy_init();
  if(hnd) {
    curl_easy_setopt(hnd, CURLOPT_URL, URL);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_ALTSVC, "log/altsvc-1908");
    ret = curl_easy_perform(hnd);

    if(!ret) {
      /* make a copy and check that this also has alt-svc activated */
      CURL *also = curl_easy_duphandle(hnd);
      if(also) {
        ret = curl_easy_perform(also);
        /* we close the second handle first, which makes it store the alt-svc
           file only to get overwritten when the next handle is closed! */
        curl_easy_cleanup(also);
      }
    }

    curl_easy_reset(hnd);

    /* using the same file name for the alt-svc cache, this clobbers the
       content just written from the 'also' handle */
    curl_easy_cleanup(hnd);
  }
  curl_global_cleanup();
  return (int)ret;
}
