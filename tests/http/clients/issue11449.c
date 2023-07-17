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
#include <unistd.h>
#include "curl/curl.h"

static size_t mycurl_onrecv_body(char *ptr, size_t size,
                                 size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static void mycurl_process(CURLM *multi_handle)
{
  CURLMsg *curl_msg = NULL;
  int msgs_left = 0;
  while((curl_msg = curl_multi_info_read(multi_handle, &msgs_left))) {
    if(curl_msg->msg == CURLMSG_DONE) {
      CURL *http_handle = curl_msg->easy_handle;
      CURLcode code = curl_msg->data.result;
      curl_multi_remove_handle(multi_handle, http_handle);
      printf("handle %p finished -> %d\n", (void *)http_handle, code);
      curl_easy_cleanup(http_handle);
    }
  }
  return;
}

int main(void)
{
  CURLM *multi_handle;
  CURL *http_handle;
  int reqid = 0, i, count;
  const char *urls[] = {
    "https://cloudflare-quic.com/",
    "https://cloudflare-quic.com/",
    "https://cloudflare-quic.com/",
    NULL
  };

  curl_global_init(CURL_GLOBAL_ALL);
  printf("%s\n", curl_version());

  multi_handle = curl_multi_init();

  count = 5;
  while(count--) {
    int still_running = 0;
    for(i = 0; urls[i]; ++i) {
      printf("New Request[%d]: %s\n", reqid++, urls[i]);
      http_handle = curl_easy_init();
      curl_easy_setopt(http_handle, CURLOPT_URL, urls[i]);
      curl_easy_setopt(http_handle, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(http_handle, CURLOPT_WRITEFUNCTION, mycurl_onrecv_body);
      curl_easy_setopt(http_handle, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
      curl_easy_setopt(http_handle, CURLOPT_TIMEOUT_MS, 10000L);
      curl_easy_setopt(http_handle, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_3ONLY);
      curl_multi_add_handle(multi_handle, http_handle);
    }

    do {
      int numfds = 0;
      curl_multi_wait(multi_handle, NULL, 0, 10, &numfds);
      curl_multi_perform(multi_handle, &still_running);
      mycurl_process(multi_handle);
    } while(still_running);
    sleep(1);
  }

  curl_multi_cleanup(multi_handle);
  return 0;
}
