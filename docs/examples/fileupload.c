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
 * Upload to a file:// URL
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for fopen() */
#endif
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <curl/curl.h>

#ifdef _WIN32
#undef stat
#define stat _stati64
#undef fstat
#define fstat _fstati64
#define fileno _fileno
#endif

int main(void)
{
  CURL *curl;
  CURLcode result;
  struct stat file_info;
  curl_off_t speed_upload, total_time;
  FILE *fd;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  fd = fopen("debugit", "rb"); /* open file to upload */
  if(!fd) {
    curl_global_cleanup();
    return 1; /* cannot continue */
  }

  /* to get the file size */
  if(fstat(fileno(fd), &file_info) != 0) {
    fclose(fd);
    curl_global_cleanup();
    return 1; /* cannot continue */
  }

  curl = curl_easy_init();
  if(curl) {
    /* upload to this place */
    curl_easy_setopt(curl, CURLOPT_URL,
                     "file:///home/dast/src/curl/debug/new");

    /* tell it to "upload" to the URL */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* set where to read from (on Windows you need to use READFUNCTION too) */
    curl_easy_setopt(curl, CURLOPT_READDATA, fd);

    /* and give the size of the upload (optional) */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)file_info.st_size);

    /* enable verbose for easier tracing */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    result = curl_easy_perform(curl);
    /* Check for errors */
    if(result != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));
    }
    else {
      /* now extract transfer info */
      curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD_T, &speed_upload);
      curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &total_time);

      fprintf(stderr, "Speed: %" CURL_FORMAT_CURL_OFF_T " bytes/sec during "
              "%" CURL_FORMAT_CURL_OFF_T
              ".%06" CURL_FORMAT_CURL_OFF_T " seconds\n",
              speed_upload,
              total_time / 1000000,
              total_time % 1000000);
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(fd);
  curl_global_cleanup();
  return 0;
}
