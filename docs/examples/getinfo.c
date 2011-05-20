/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;

  /* http://curl.haxx.se/libcurl/c/curl_easy_init.html */
  curl = curl_easy_init();
  if(curl) {
    /* http://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTURL */
    curl_easy_setopt(curl, CURLOPT_URL, "http://www.example.com/");
    /* http://curl.haxx.se/libcurl/c/curl_easy_perform.html */
    res = curl_easy_perform(curl);

    if(CURLE_OK == res) {
      char *ct;
      /* ask for the content-type */
      /* http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html */
      res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

      if((CURLE_OK == res) && ct)
        printf("We received Content-Type: %s\n", ct);
    }

    /* always cleanup */
    /* http://curl.haxx.se/libcurl/c/curl_easy_cleanup.html */
    curl_easy_cleanup(curl);
  }
  return 0;
}
