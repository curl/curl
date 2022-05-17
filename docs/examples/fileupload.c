/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <stdio.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;
  struct stat file_info;
  curl_off_t speed_upload, total_time;
  FILE *fd;

  fd = fopen("debugit", "rb"); /* open file to upload */
  if(!fd)
    return 1; /* cannot continue */

  /* to get the file size */
  if(fstat(fileno(fd), &file_info) != 0)
    return 1; /* cannot continue */

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

    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
    else {
      /* now extract transfer info */
      curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD_T, &speed_upload);
      curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &total_time);

      fprintf(stderr, "Speed: %lu bytes/sec during %lu.%06lu seconds\n",
              (unsigned long)speed_upload,
              (unsigned long)(total_time / 1000000),
              (unsigned long)(total_time % 1000000));
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(fd);
  return 0;
}
