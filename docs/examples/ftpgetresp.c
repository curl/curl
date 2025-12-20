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
 * Similar to ftpget.c but also stores the received response-lines
 * in a separate file using our own callback!
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for fopen() */
#endif
#endif

#include <stdio.h>

#include <curl/curl.h>

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *data)
{
  FILE *writehere = (FILE *)data;
  return fwrite(ptr, size, nmemb, writehere);
}

#define FTPBODY    "ftp-list"
#define FTPHEADERS "ftp-responses"

int main(void)
{
  CURL *curl;
  CURLcode result;
  FILE *ftpfile;
  FILE *respfile;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  /* local filename to store the file as */
  ftpfile = fopen(FTPBODY, "wb"); /* b is binary, needed on Windows */
  if(!ftpfile) {
    curl_global_cleanup();
    return 1;
  }

  /* local filename to store the FTP server's response lines in */
  respfile = fopen(FTPHEADERS, "wb"); /* b is binary, needed on Windows */
  if(!respfile) {
    fclose(ftpfile);
    curl_global_cleanup();
    return 1;
  }

  curl = curl_easy_init();
  if(curl) {
    /* Get a file listing from sunet */
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://ftp.example.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ftpfile);
    /* If you intend to use this on Windows with a libcurl DLL, you must use
       CURLOPT_WRITEFUNCTION as well */
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, respfile);
    result = curl_easy_perform(curl);
    /* Check for errors */
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  fclose(ftpfile);  /* close the local file */
  fclose(respfile); /* close the response file */

  curl_global_cleanup();

  return (int)result;
}
