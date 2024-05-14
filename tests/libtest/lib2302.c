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

#ifdef USE_WEBSOCKETS

struct ws_data {
  CURL *easy;
  char buf[1024*1024];
  size_t blen;
  size_t nwrites;
  int has_meta;
  int meta_flags;
};

static void flush_data(struct ws_data *wd)
{
  size_t i;

  if(!wd->nwrites)
    return;

  for(i = 0; i < wd->blen; ++i)
    printf("%02x ", (unsigned char)wd->buf[i]);

  printf("\n");
  if(wd->has_meta)
    printf("RECFLAGS: %x\n", wd->meta_flags);
  else
    fprintf(stderr, "RECFLAGS: NULL\n");
  wd->blen = 0;
  wd->nwrites = 0;
}

static size_t add_data(struct ws_data *wd, const char *buf, size_t blen,
                       const struct curl_ws_frame *meta)
{
  if((wd->nwrites == 0) ||
     (!!meta != !!wd->has_meta) ||
     (meta && meta->flags != wd->meta_flags)) {
    if(wd->nwrites > 0)
      flush_data(wd);
    wd->has_meta = (meta != NULL);
    wd->meta_flags = meta? meta->flags : 0;
  }

  if(wd->blen + blen > sizeof(wd->buf)) {
    return 0;
  }
  memcpy(wd->buf + wd->blen, buf, blen);
  wd->blen += blen;
  wd->nwrites++;
  return blen;
}


static size_t writecb(char *buffer, size_t size, size_t nitems, void *p)
{
  struct ws_data *ws_data = p;
  size_t incoming = nitems;
  const struct curl_ws_frame *meta;
  (void)size;

  meta = curl_ws_meta(ws_data->easy);
  incoming = add_data(ws_data, buffer, incoming, meta);

  if(nitems != incoming)
    fprintf(stderr, "returns error from callback\n");
  return nitems;
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct ws_data ws_data;


  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    memset(&ws_data, 0, sizeof(ws_data));
    ws_data.easy = curl;

    curl_easy_setopt(curl, CURLOPT_URL, URL);
    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "webbie-sox/3");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ws_data);
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %d\n", res);
    /* always cleanup */
    curl_easy_cleanup(curl);
    flush_data(&ws_data);
  }
  curl_global_cleanup();
  return res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
