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
#include "first.h"

/* verify that curl_easy_pause() and the WebSocket API are protected
   against calls from the debug callback, both during a transfer and from
   a CONNECT_ONLY handle after curl_easy_perform() returned */

static CURL *t1694_curl;
static const char *t1694_phase;
static int t1694_called;

static size_t t1694_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userp)
{
  (void)ptr;
  (void)userp;
  return size * nmemb;
}

static int t1694_debug_cb(CURL *curl, curl_infotype type, char *data,
                          size_t size, void *userp)
{
  (void)curl;
  (void)data;
  (void)size;
  (void)userp;
  if((type == CURLINFO_TEXT) && t1694_phase && !t1694_called) {
    CURLcode result;
    const struct curl_ws_frame *meta;
    char buffer[8];
    size_t n = 0;

    t1694_called = 1;
    result = curl_easy_pause(t1694_curl, CURLPAUSE_ALL);
    curl_mprintf("%s: curl_easy_pause returned %d\n", t1694_phase,
                 (int)result);
    result = curl_ws_recv(t1694_curl, buffer, sizeof(buffer), &n, &meta);
    curl_mprintf("%s: curl_ws_recv returned %d\n", t1694_phase, (int)result);
    result = curl_ws_send(t1694_curl, "x", 1, &n, 0, CURLWS_TEXT);
    curl_mprintf("%s: curl_ws_send returned %d\n", t1694_phase, (int)result);
    result = curl_ws_start_frame(t1694_curl, CURLWS_TEXT, 1);
    curl_mprintf("%s: curl_ws_start_frame returned %d\n", t1694_phase,
                 (int)result);
  }
  return 0;
}

static CURLcode test_lib1694(const char *URL)
{
  CURLcode result = CURLE_OK;
  size_t n = 0;

  global_init(CURL_GLOBAL_ALL);
  /* [WS] traces make the debug callback run inside curl_ws_send() */
  curl_global_trace("ws");

  /* the debug callback runs during the transfer */
  easy_init(t1694_curl);

  easy_setopt(t1694_curl, CURLOPT_URL, URL);
  easy_setopt(t1694_curl, CURLOPT_TIMEOUT, 7L);
  easy_setopt(t1694_curl, CURLOPT_WRITEFUNCTION, t1694_write_cb);
  easy_setopt(t1694_curl, CURLOPT_DEBUGFUNCTION, t1694_debug_cb);
  easy_setopt(t1694_curl, CURLOPT_VERBOSE, 1L);

  t1694_phase = "transfer";
  t1694_called = 0;
  result = curl_easy_perform(t1694_curl);
  if(result)
    goto test_cleanup;
  curl_easy_cleanup(t1694_curl);
  t1694_curl = NULL;

  /* the debug callback runs inside curl_ws_send() on a CONNECT_ONLY handle
     that curl_easy_perform() has returned for */
  easy_init(t1694_curl);

  easy_setopt(t1694_curl, CURLOPT_URL, URL);
  easy_setopt(t1694_curl, CURLOPT_TIMEOUT, 7L);
  easy_setopt(t1694_curl, CURLOPT_CONNECT_ONLY, 2L);
  easy_setopt(t1694_curl, CURLOPT_DEBUGFUNCTION, t1694_debug_cb);
  easy_setopt(t1694_curl, CURLOPT_VERBOSE, 1L);

  t1694_phase = NULL;
  result = curl_easy_perform(t1694_curl);
  if(result)
    goto test_cleanup;
  t1694_phase = "connect-only";
  t1694_called = 0;
  result = curl_ws_send(t1694_curl, "x", 1, &n, 0, CURLWS_TEXT);
  curl_mprintf("curl_ws_send returned %d\n", (int)result);

test_cleanup:

  curl_easy_cleanup(t1694_curl);
  curl_global_cleanup();

  return result;
}
