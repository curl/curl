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
 * Delete a single file from an FTP server.
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

static size_t write_cb(void *buffer, size_t size, size_t nmemb, void *stream)
{
  (void)buffer;
  (void)stream;
  return size * nmemb;
}

int main(void)
{
  CURL *curl;
  CURLcode result;
  struct curl_slist *headerlist = NULL;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    /*
     * You better replace the URL with one that works!
     */
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://ftp.example.com/");
    /* Define our callback to get called when there is data to be written */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    /* Switch on full protocol/debug output */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* build a list of commands to pass to libcurl */
    headerlist = curl_slist_append(headerlist, "DELE file-to-remove");

    /* pass in list of FTP commands to run after the transfer */
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);

    result = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* clean up the FTP commands list */
    curl_slist_free_all(headerlist);

    if(result != CURLE_OK) {
      /* we failed */
      fprintf(stderr, "curl told us %d\n", result);
    }
  }

  curl_global_cleanup();

  return (int)result;
}
