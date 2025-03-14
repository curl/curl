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

/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
  fprintf(stderr,
          "ws: curl_ws_send returned %d, sent %zu\n", result, sent);
}

static void websocket_frame(CURL *curl, FILE *save, int expected_flags)
{
  char buffer[256];
  const struct curl_ws_frame *meta;
  size_t nread;
  size_t total_read = 0;

  /* silence "unused parameter" warning */
  (void)expected_flags;

  /* Frames are expected to have 4097 bytes */
  while(true) {
    CURLcode result =
      curl_ws_recv(curl, buffer, sizeof(buffer), &nread, &meta);
    if(result) {
      if(result == CURLE_AGAIN)
        /* crude busy-loop */
        continue;
      printf("curl_ws_recv returned %d\n", result);
      return;
    }
    printf("%d: nread %zu Age %d Flags %x "
           "Offset %" CURL_FORMAT_CURL_OFF_T " "
           "Bytesleft %" CURL_FORMAT_CURL_OFF_T "\n",
           (int)total_read,
           nread, meta->age, meta->flags, meta->offset, meta->bytesleft);
    assert(meta->flags == expected_flags);
    total_read += nread;
    fwrite(buffer, 1, nread, save);
    /* exit condition */
    if(meta->bytesleft == 0) {
      break;
    }
  }

  assert(total_read == 4097);
}

static void websocket(CURL *curl)
{
  FILE *save = fopen(libtest_arg2, FOPEN_WRITETEXT);
  if(!save)
    return;

  /* Three frames are expected */
  websocket_frame(curl, save, CURLWS_TEXT | CURLWS_CONT);
  websocket_frame(curl, save, CURLWS_TEXT | CURLWS_CONT);
  websocket_frame(curl, save, CURLWS_TEXT);

  fclose(save);
  websocket_close(curl);
}

CURLcode test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "websocket/2311");
    libtest_debug_config.nohex = 1;
    libtest_debug_config.tracetime = 1;
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &libtest_debug_config);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %d\n", res);
    if(res == CURLE_OK)
      websocket(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
