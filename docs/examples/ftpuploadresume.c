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
 * Upload to FTP, resuming failed transfers. Active mode.
 * </DESC>
 */

#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>

/* parse headers for Content-Length */
static size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb,
                                   void *stream)
{
  int r;
  long len = 0;

  r = sscanf(ptr, "Content-Length: %ld\n", &len);
  if(r == 1)
    *((long *) stream) = len;

  return size * nmemb;
}

/* discard downloaded data */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)ptr;
  (void)stream;
  return size * nmemb;
}

/* read data to upload */
static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  FILE *f = stream;
  size_t n;

  if(ferror(f))
    return CURL_READFUNC_ABORT;

  n = fread(ptr, size, nmemb, f) * size;

  return n;
}


static int upload(CURL *curl, const char *remotepath,
                  const char *localpath, long timeout, long tries)
{
  FILE *f;
  long uploaded_len = 0;
  CURLcode res = CURLE_GOT_NOTHING;
  int c;

  f = fopen(localpath, "rb");
  if(!f) {
#ifndef UNDER_CE
    perror(NULL);
#endif
    return 0;
  }

  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  curl_easy_setopt(curl, CURLOPT_URL, remotepath);

  if(timeout)
    curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, timeout);

  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, getcontentlengthfunc);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &uploaded_len);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
  curl_easy_setopt(curl, CURLOPT_READDATA, f);

  /* enable active mode */
  curl_easy_setopt(curl, CURLOPT_FTPPORT, "-");

  /* allow the server no more than 7 seconds to connect back */
  curl_easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, 7000L);

  curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, 1L);

  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  for(c = 0; (res != CURLE_OK) && (c < tries); c++) {
    /* are we resuming? */
    if(c) { /* yes */
      /* determine the length of the file already written */

      /*
       * With NOBODY and NOHEADER, libcurl issues a SIZE command, but the only
       * way to retrieve the result is to parse the returned Content-Length
       * header. Thus, getcontentlengthfunc(). We need write_cb() above
       * because HEADER dumps the headers to stdout without it.
       */
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

      res = curl_easy_perform(curl);
      if(res != CURLE_OK)
        continue;

      curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(curl, CURLOPT_HEADER, 0L);

      fseek(f, uploaded_len, SEEK_SET);

      curl_easy_setopt(curl, CURLOPT_APPEND, 1L);
    }
    else { /* no */
      curl_easy_setopt(curl, CURLOPT_APPEND, 0L);
    }

    res = curl_easy_perform(curl);
  }

  fclose(f);

  if(res == CURLE_OK)
    return 1;
  else {
    fprintf(stderr, "%s\n", curl_easy_strerror(res));
    return 0;
  }
}

int main(void)
{
  CURL *curl = NULL;

  CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
  if(res)
    return (int)res;

  curl = curl_easy_init();
  if(curl) {
    upload(curl, "ftp://user:pass@example.com/path/file", "C:\\file", 0, 3);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  return 0;
}
