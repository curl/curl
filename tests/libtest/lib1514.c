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
/*
 * Make sure libcurl does not send a `Content-Length: -1` header when HTTP POST
 * size is unknown.
 */

#include "first.h"

#include "memdebug.h"

struct t1514_WriteThis {
  char *readptr;
  size_t sizeleft;
};

static size_t t1514_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t1514_WriteThis *pooh = (struct t1514_WriteThis *)userp;

  if(size*nmemb < 1)
    return 0;

  if(pooh->sizeleft) {
    *ptr = pooh->readptr[0]; /* copy one single byte */
    pooh->readptr++;                 /* advance pointer */
    pooh->sizeleft--;                /* less data left */
    return 1;                        /* we return 1 byte at a time! */
  }

  return 0;                         /* no more data left to deliver */
}

static CURLcode test_lib1514(const char *URL)
{
  CURL *curl;
  CURLcode result = CURLE_OK;
  CURLcode res = CURLE_OK;

  static char testdata[] = "dummy";

  struct t1514_WriteThis pooh = { testdata, sizeof(testdata)-1 };

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_POST, 1L);
  /* Purposely omit to set CURLOPT_POSTFIELDSIZE */
  easy_setopt(curl, CURLOPT_READFUNCTION, t1514_read_cb);
  easy_setopt(curl, CURLOPT_READDATA, &pooh);

  if(testnum == 1539) {
    /* speak HTTP 1.0 - no chunked! */
    easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  }

  result = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
