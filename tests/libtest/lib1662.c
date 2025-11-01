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

struct t1662_WriteThis {
  size_t sizeleft;
};

static size_t t1662_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  static const char testdata[] = "mooaaa";

  struct t1662_WriteThis *pooh = (struct t1662_WriteThis *)userp;
  size_t len = strlen(testdata);

  if(size*nmemb < len)
    return 0;

  if(pooh->sizeleft) {
    memcpy(ptr, testdata, strlen(testdata));
    pooh->sizeleft = 0;
    return len;
  }

  return 0;                         /* no more data left to deliver */
}

static CURLcode test_lib1662(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl;
  curl_mime *mime1;
  curl_mimepart *part1;
  struct t1662_WriteThis pooh = { 1 };

  mime1 = NULL;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    mime1 = curl_mime_init(curl);
    if(mime1) {
      part1 = curl_mime_addpart(mime1);
      curl_mime_data_cb(part1, -1, t1662_read_cb, NULL, NULL, &pooh);
      curl_mime_filename(part1, "poetry.txt");
      curl_mime_name(part1, "content");
      curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime1);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/2000");
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
      curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
      res = curl_easy_perform(curl);
    }
  }

  curl_easy_cleanup(curl);
  curl_mime_free(mime1);
  curl_global_cleanup();
  return res;
}
