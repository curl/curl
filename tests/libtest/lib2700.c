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
#include "testtrace.h"
#include "memdebug.h"

#ifndef CURL_DISABLE_WEBSOCKETS

static const char *descr_flags(int flags)
{
  if(flags & CURLWS_TEXT)
    return flags & CURLWS_CONT ? "txt ---" : "txt fin";
  if(flags & CURLWS_BINARY)
    return flags & CURLWS_CONT ? "bin ---" : "bin fin";
  if(flags & CURLWS_PING)
    return "ping";
  if(flags & CURLWS_PONG)
    return "pong";
  if(flags & CURLWS_CLOSE)
    return "close";
  assert(false);
  return "";
}

static CURLcode send_header(CURL *curl, int flags, size_t size)
{
  CURLcode res = CURLE_OK;
  size_t nsent;

retry:
  res = curl_ws_send(curl, NULL, 0, &nsent, (curl_off_t)size,
                     flags | CURLWS_OFFSET);
  if(res == CURLE_AGAIN) {
    assert(nsent == 0);
    goto retry;
  }
  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_ws_send() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    assert(nsent == 0);
    return res;
  }

  assert(nsent == 0);

  return CURLE_OK;
}

static CURLcode recv_header(CURL *curl, int *flags, curl_off_t *offset,
                            curl_off_t *bytesleft)
{
  CURLcode res = CURLE_OK;
  size_t nread;
  const struct curl_ws_frame *meta;

  *flags = 0;
  *offset = 0;
  *bytesleft = 0;

retry:
  res = curl_ws_recv(curl, NULL, 0, &nread, &meta);
  if(res == CURLE_AGAIN) {
    assert(nread == 0);
    goto retry;
  }
  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_ws_recv() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    assert(nread == 0);
    return res;
  }

  assert(nread == 0);
  assert(meta != NULL);
  assert(meta->flags);
  assert(meta->offset == 0);

  *flags = meta->flags;
  *offset = meta->offset;
  *bytesleft = meta->bytesleft;

  curl_mfprintf(stdout, "%s [%" FMT_OFF_T "]", descr_flags(meta->flags),
                meta->bytesleft);

  if(meta->bytesleft > 0)
    curl_mfprintf(stdout, " ");

  res = send_header(curl, meta->flags, (size_t)meta->bytesleft);
  if(res)
    return res;

  return CURLE_OK;
}

static CURLcode send_chunk(CURL *curl, int flags, const char *buffer,
                           size_t size, size_t *offset)
{
  CURLcode res = CURLE_OK;
  size_t nsent;

retry:
    res = curl_ws_send(curl, buffer + *offset, size - *offset, &nsent, 0,
                       flags);
  if(res == CURLE_AGAIN) {
    assert(nsent == 0);
    goto retry;
  }
  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_ws_send() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    assert(nsent == 0);
    return res;
  }

  assert(nsent <= size - *offset);

  *offset += nsent;

  return CURLE_OK;
}

static CURLcode recv_chunk(CURL *curl, int flags, curl_off_t *offset,
                           curl_off_t *bytesleft)
{
  CURLcode res = CURLE_OK;
  char buffer[256];
  size_t nread;
  const struct curl_ws_frame *meta;
  size_t sendoffset = 0;

retry:
  res = curl_ws_recv(curl, buffer, sizeof(buffer), &nread, &meta);
  if(res == CURLE_AGAIN) {
    assert(nread == 0);
    goto retry;
  }
  if(res) {
    curl_mfprintf(stderr, "%s:%d curl_ws_recv() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    assert(nread == 0);
    return res;
  }

  assert(nread <= sizeof(buffer));
  assert(meta != NULL);
  assert(meta->flags == flags);
  assert(meta->offset == *offset);
  assert(meta->bytesleft == (*bytesleft - (curl_off_t)nread));

  *offset += nread;
  *bytesleft -= nread;

  fwrite(buffer, 1, nread, stdout);

  while(sendoffset < nread) {
    res = send_chunk(curl, flags, buffer, nread, &sendoffset);
    if(res)
      return res;
  }

  return CURLE_OK;
}

static CURLcode recv_frame(CURL *curl, bool *stop)
{
  CURLcode res = CURLE_OK;
  int flags = 0;
  curl_off_t offset = 0;
  curl_off_t bytesleft = 0;

  res = recv_header(curl, &flags, &offset, &bytesleft);
  if(res)
    return res;

  while(bytesleft > 0) {
    res = recv_chunk(curl, flags, &offset, &bytesleft);
    if(res)
      return res;
  }

  if(flags & CURLWS_CLOSE)
    *stop = true;

  curl_mfprintf(stdout, "\n");

  return res;
}

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  bool stop = false;
  CURL *curl;

  global_init(CURL_GLOBAL_ALL);
  curl_global_trace("ws");
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_USERAGENT, "client/test2700");
  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  easy_setopt(curl, CURLOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
  if(!getenv("LIB2700_AUTO_PONG"))
    easy_setopt(curl, CURLOPT_WS_OPTIONS, (long)CURLWS_NOAUTOPONG);

  res = curl_easy_perform(curl);
  if(res) {
    curl_mfprintf(stderr,
                  "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                  __FILE__, __LINE__, res, curl_easy_strerror(res));
    goto test_cleanup;
  }

  while(!stop) {
    res = recv_frame(curl, &stop);
    if(res)
      goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
