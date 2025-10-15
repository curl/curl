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
/* <DESC>
 * Connection cache shared between easy handles with the share interface
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

static void my_lock(CURL *handle, curl_lock_data data,
                    curl_lock_access laccess, void *useptr)
{
  (void)handle;
  (void)data;
  (void)laccess;
  (void)useptr;
  fprintf(stderr, "-> Mutex lock\n");
}

static void my_unlock(CURL *handle, curl_lock_data data, void *useptr)
{
  (void)handle;
  (void)data;
  (void)useptr;
  fprintf(stderr, "<- Mutex unlock\n");
}

int main(void)
{
  CURLSH *share;
  int i;

  share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

  curl_share_setopt(share, CURLSHOPT_LOCKFUNC, my_lock);
  curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, my_unlock);

  /* Loop the transfer and cleanup the handle properly every lap. This still
     reuses connections since the pool is in the shared object! */

  for(i = 0; i < 3; i++) {
    CURL *curl = curl_easy_init();
    if(curl) {
      CURLcode res;

      curl_easy_setopt(curl, CURLOPT_URL, "https://curl.se/");

      /* use the share object */
      curl_easy_setopt(curl, CURLOPT_SHARE, share);

      /* Perform the request, res gets the return code */
      res = curl_easy_perform(curl);
      /* Check for errors */
      if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

      /* always cleanup */
      curl_easy_cleanup(curl);
    }
  }

  curl_share_cleanup(share);
  return 0;
}
