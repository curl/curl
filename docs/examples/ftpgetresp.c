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

/*
 * Similar to ftpget.c but this also stores the received response-lines
 * in a separate file using our own callback!
 *
 * This functionality was introduced in libcurl 7.9.3.
 */

static size_t
write_response(void *ptr, size_t size, size_t nmemb, void *data)
{
  FILE *writehere = (FILE *)data;
  return fwrite(ptr, size, nmemb, writehere);
}

int main(void)
{
  CURL *curl;
  CURLcode res;
  FILE *ftpfile;
  FILE *respfile;

  /* local file name to store the file as */
  ftpfile = fopen("ftp-list", "wb"); /* b is binary, needed on win32 */

  /* local file name to store the FTP server's response lines in */
  respfile = fopen("ftp-responses", "wb"); /* b is binary, needed on win32 */

  curl = curl_easy_init();
  if(curl) {
    /* Get a file listing from sunet */
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://ftp.example.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ftpfile);
    /* If you intend to use this on windows with a libcurl DLL, you must use
       CURLOPT_WRITEFUNCTION as well */
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, respfile);
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  fclose(ftpfile); /* close the local file */
  fclose(respfile); /* close the response file */

  return 0;
}
