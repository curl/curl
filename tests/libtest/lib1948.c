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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

typedef struct
{
  char *buf;
  size_t len;
} put_buffer;

static size_t put_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  put_buffer *putdata = (put_buffer *)stream;
  size_t totalsize = size * nmemb;
  size_t tocopy = (putdata->len < totalsize) ? putdata->len : totalsize;
  memcpy(ptr, putdata->buf, tocopy);
  putdata->len -= tocopy;
  putdata->buf += tocopy;
  return tocopy;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  const char *testput = "This is test PUT data\n";
  put_buffer pbuf;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  easy_init(curl);

  /* PUT */
  easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  easy_setopt(curl, CURLOPT_HEADER, 1L);
  easy_setopt(curl, CURLOPT_READFUNCTION, put_callback);
  pbuf.buf = (char *)CURL_UNCONST(testput);
  pbuf.len = strlen(testput);
  easy_setopt(curl, CURLOPT_READDATA, &pbuf);
  easy_setopt(curl, CURLOPT_INFILESIZE, (long)strlen(testput));
  easy_setopt(curl, CURLOPT_URL, URL);
  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  /* POST */
  easy_setopt(curl, CURLOPT_POST, 1L);
  easy_setopt(curl, CURLOPT_POSTFIELDS, testput);
  easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(testput));
  res = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
