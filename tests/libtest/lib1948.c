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
 * are also available at https://fetch.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
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

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  const char *testput = "This is test PUT data\n";
  put_buffer pbuf;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  easy_init(fetch);

  /* PUT */
  easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);
  easy_setopt(fetch, FETCHOPT_HEADER, 1L);
  easy_setopt(fetch, FETCHOPT_READFUNCTION, put_callback);
  pbuf.buf = (char *)testput;
  pbuf.len = strlen(testput);
  easy_setopt(fetch, FETCHOPT_READDATA, &pbuf);
  easy_setopt(fetch, FETCHOPT_INFILESIZE, (long)strlen(testput));
  easy_setopt(fetch, FETCHOPT_URL, URL);
  res = fetch_easy_perform(fetch);
  if(res)
    goto test_cleanup;

  /* POST */
  easy_setopt(fetch, FETCHOPT_POST, 1L);
  easy_setopt(fetch, FETCHOPT_POSTFIELDS, testput);
  easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)strlen(testput));
  res = fetch_easy_perform(fetch);

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();
  return res;
}
