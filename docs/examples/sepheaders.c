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
 * Simple HTTP GET that stores the headers in a separate file
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for fopen() */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>

#include <curl/curl.h>

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int main(void)
{
  CURL *curl;

  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  /* init the curl session */
  curl = curl_easy_init();
  if(curl) {
    static const char *headerfilename = "head.out";
    FILE *headerfile;
    static const char *bodyfilename = "body.out";
    FILE *bodyfile;

    /* set URL to get */
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* no progress meter please */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    /* open the header file */
    headerfile = fopen(headerfilename, "wb");
    if(!headerfile) {
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return -1;
    }

    /* open the body file */
    bodyfile = fopen(bodyfilename, "wb");
    if(!bodyfile) {
      curl_easy_cleanup(curl);
      fclose(headerfile);
      curl_global_cleanup();
      return -1;
    }

    /* we want the headers be written to this file handle */
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, headerfile);

    /* we want the body be written to this file handle instead of stdout */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, bodyfile);

    /* get it! */
    result = curl_easy_perform(curl);

    /* close the header file */
    fclose(headerfile);

    /* close the body file */
    fclose(bodyfile);

    /* cleanup curl stuff */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return (int)result;
}
