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
#include "test.h"

static char data[]="mooaaa";

struct WriteThis {
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  size_t len = strlen(data);

  if(size*nmemb < len)
    return 0;

  if(pooh->sizeleft) {
    memcpy(ptr, data, strlen(data));
    pooh->sizeleft = 0;
    return len;
  }

  return 0;                         /* no more data left to deliver */
}


CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *hnd;
  curl_mime *mime1;
  curl_mimepart *part1;
  struct WriteThis pooh = { 1 };

  mime1 = NULL;

  global_init(CURL_GLOBAL_ALL);

  hnd = curl_easy_init();
  if(hnd) {
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, URL);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    mime1 = curl_mime_init(hnd);
    if(mime1) {
      part1 = curl_mime_addpart(mime1);
      curl_mime_data_cb(part1, -1, read_callback, NULL, NULL, &pooh);
      curl_mime_filename(part1, "poetry.txt");
      curl_mime_name(part1, "content");
      curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime1);
      curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/2000");
      curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
      curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION,
                       (long)CURL_HTTP_VERSION_2TLS);
      curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
      curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
      res = curl_easy_perform(hnd);
    }
  }

  curl_easy_cleanup(hnd);
  curl_mime_free(mime1);
  curl_global_cleanup();
  return res;
}
