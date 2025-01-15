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
#include "test.h"

#include "warnless.h"
#include "memdebug.h"

/* For Windows, mainly (may be moved in a config file?) */
#ifndef STDIN_FILENO
  #define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
  #define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
  #define STDERR_FILENO 2
#endif

CURLcode test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);

  if(!res) {
    /* we are connected, now get an HTTP document the raw way */
    const char *request =
      "GET /556 HTTP/1.1\r\n"
      "Host: ninja\r\n\r\n";
    const char *sbuf = request;
    size_t sblen = strlen(request);
    size_t nwritten = 0, nread = 0;

    do {
      char buf[1024];

      if(sblen) {
        res = curl_easy_send(curl, sbuf, sblen, &nwritten);
        if(res && res != CURLE_AGAIN)
          break;
        if(nwritten > 0) {
          sbuf += nwritten;
          sblen -= nwritten;
        }
      }

      /* busy-read like crazy */
      res = curl_easy_recv(curl, buf, sizeof(buf), &nread);

      if(nread) {
        /* send received stuff to stdout */
        if(!write(STDOUT_FILENO, buf, nread))
          break;
      }

    } while((res == CURLE_OK && nread) || (res == CURLE_AGAIN));

    if(res && res != CURLE_AGAIN)
      res = TEST_ERR_FAILURE;
  }

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
