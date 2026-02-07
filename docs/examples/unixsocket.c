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
 * Access HTTP server over Unix domain socket
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#ifdef USE_ABSTRACT
/*
 * The abstract socket namespace is a nonportable Linux extension. The name
 * has no connection with file system pathnames.
 */
#define ABSTRACT "http-unix-domain"
#else
#define PATH "/tmp/http-unix-domain"
#endif

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

#ifdef USE_ABSTRACT
    curl_easy_setopt(curl, CURLOPT_ABSTRACT_UNIX_SOCKET, ABSTRACT);
#else
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, PATH);
#endif

    /* Perform the request, result gets the return code */
    result = curl_easy_perform(curl);
    /* Check for errors */
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)result;
}
