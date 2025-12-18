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
 * Checks a single file's size and mtime from an FTP server.
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for ctime(), fopen() */
#endif
#endif

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
  (void)ptr;
  (void)data;
  /* we are not interested in the headers itself,
     so we only return the size we would have saved ... */
  return (size_t)(size * nmemb);
}

int main(void)
{
  char ftpurl[] = "ftp://ftp.example.com/gnu/binutils/binutils-2.19.1.tar.bz2";
  CURL *curl;
  CURLcode result;
  long filetime = -1;
  curl_off_t filesize = 0;
  const char *filename = strrchr(ftpurl, '/') + 1;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, ftpurl);
    /* No download if the file */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    /* Ask for filetime */
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
    /* Switch on full protocol/debug output */
    /* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */

    result = curl_easy_perform(curl);

    if(CURLE_OK == result) {
      /* https://curl.se/libcurl/c/curl_easy_getinfo.html */
      result = curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if((CURLE_OK == result) && (filetime >= 0)) {
        time_t file_time = (time_t)filetime;
        printf("filetime %s: %s", filename, ctime(&file_time));
      }
      result = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                                 &filesize);
      if((CURLE_OK == result) && (filesize > 0))
        printf("filesize %s: %" CURL_FORMAT_CURL_OFF_T " bytes\n",
               filename, filesize);
    }
    else {
      /* we failed */
      fprintf(stderr, "curl told us %d\n", result);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return (int)result;
}
