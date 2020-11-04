/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* <DESC>
 * single download with the multi interface's curl_multi_poll
 * </DESC>
 */

#include <stdio.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

/* curl stuff */
#include <curl/curl.h>

int main(void)
{
  CURL *http_handle;
  CURLM *multi_handle;
  int still_running = 1; /* keep number of running handles */

  curl_global_init(CURL_GLOBAL_DEFAULT);

  http_handle = curl_easy_init();

  curl_easy_setopt(http_handle, CURLOPT_URL, "https://www.example.com/");

  multi_handle = curl_multi_init();

  curl_multi_add_handle(multi_handle, http_handle);

  while(still_running) {
    CURLMcode mc; /* curl_multi_poll() return code */
    int numfds;

    /* we start some action by calling perform right away */
    mc = curl_multi_perform(multi_handle, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, &numfds);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_wait() failed, code %d.\n", mc);
      break;
    }
  }

  curl_multi_remove_handle(multi_handle, http_handle);
  curl_easy_cleanup(http_handle);
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();

  return 0;
}
