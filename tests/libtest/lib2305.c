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

#ifdef USE_WEBSOCKETS

/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
  fprintf(stderr,
          "ws: curl_ws_send returned %u, sent %u\n", (int)result, (int)sent);
}

static void websocket(CURL *curl)
{
  char buffer[256];
  const struct curl_ws_frame *meta;
  size_t nread;
  size_t i = 0;
  FILE *save = fopen(libtest_arg2, FOPEN_WRITETEXT);
  if(!save)
    return;

  /* Three 4097-bytes frames are expected, 12291 bytes */
  while(i < 12291) {
    CURLcode result =
      curl_ws_recv(curl, buffer, sizeof(buffer), &nread, &meta);
    if(result) {
      if(result == CURLE_AGAIN)
        /* crude busy-loop */
        continue;
      printf("curl_ws_recv returned %d\n", (int)result);
      return;
    }
    printf("%u: nread %zu Age %u Flags %x "
           "Offset %" CURL_FORMAT_CURL_OFF_T " "
           "Bytesleft %" CURL_FORMAT_CURL_OFF_T "\n",
           (int)i,
           nread, meta->age, meta->flags, meta->offset, meta->bytesleft);
    i += meta->len;
    fwrite(buffer, 1, nread, save);
  }
  fclose(save);

  websocket_close(curl);
}

extern struct libtest_trace_cfg libtest_debug_config;

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "websocket/2304");
    libtest_debug_config.nohex = 1;
    libtest_debug_config.tracetime = 1;
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &libtest_debug_config);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %u\n", (int)res);
    if(res == CURLE_OK)
      websocket(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
