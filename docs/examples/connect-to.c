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
 * Use CURLOPT_CONNECT_TO to connect to "wrong" hostname
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  /*
    Each single string should be written using the format
    HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT where HOST is the host of the
    request, PORT is the port of the request, CONNECT-TO-HOST is the host name
    to connect to, and CONNECT-TO-PORT is the port to connect to.
   */
  /* instead of curl.se:443, it resolves and uses example.com:443 but in other
     aspects work as if it still is curl.se */
  struct curl_slist *host = curl_slist_append(NULL,
                                              "curl.se:443:example.com:443");

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_CONNECT_TO, host);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, "https://curl.se/");

    /* since this connects to the wrong host, checking the host name in the
       server certificate fails, so unless we disable the check libcurl
       returns CURLE_PEER_FAILED_VERIFICATION */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    /* Letting the wrong host name in the certificate be okay, the transfer
       goes through but (most likely) causes a 404 or similar because it sends
       an unknown name in the Host: header field */
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_slist_free_all(host);

  return (int)res;
}
