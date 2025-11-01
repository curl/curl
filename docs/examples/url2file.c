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
 * Download a given URL into a local file named page.out.
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>

#include <curl/curl.h>

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int main(int argc, char *argv[])
{
  static const char *pagefilename = "page.out";

  CURLcode res;
  CURL *curl;

  if(argc < 2) {
    printf("Usage: %s <URL>\n", argv[0]);
    return 1;
  }

  res = curl_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fprintf(stderr, "Could not init curl\n");
    return (int)res;
  }

  /* init the curl session */
  curl = curl_easy_init();
  if(curl) {
    FILE *pagefile;

    /* set URL to get here */
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);

    /* Switch on full protocol/debug output while testing */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* disable progress meter, set to 0L to enable it */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    /* open the file */
    pagefile = fopen(pagefilename, "wb");
    if(pagefile) {

      /* write the page body to this file handle */
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, pagefile);

      /* get it! */
      res = curl_easy_perform(curl);

      /* close the header file */
      fclose(pagefile);
    }

    /* cleanup curl stuff */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return (int)res;
}
