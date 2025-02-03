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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "test.h"
#include "testtrace.h"
#include "memdebug.h"

#ifndef FETCH_DISABLE_WEBSOCKETS

/* just close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  FETCHcode result =
      fetch_ws_send(fetch, "", 0, &sent, 0, FETCHWS_CLOSE);
  fprintf(stderr,
          "ws: fetch_ws_send returned %d, sent %d\n", result, (int)sent);
}

static void websocket(FETCH *fetch)
{
  char buffer[256];
  const struct fetch_ws_frame *meta;
  size_t nread;
  size_t i = 0;
  FILE *save = fopen(libtest_arg2, FOPEN_WRITETEXT);
  if (!save)
    return;

  /* Three 4097-bytes frames are expected, 12291 bytes */
  while (i < 12291)
  {
    FETCHcode result =
        fetch_ws_recv(fetch, buffer, sizeof(buffer), &nread, &meta);
    if (result)
    {
      if (result == FETCHE_AGAIN)
        /* crude busy-loop */
        continue;
      fclose(save);
      printf("fetch_ws_recv returned %d\n", result);
      return;
    }
    printf("%d: nread %zu Age %d Flags %x "
           "Offset %" FETCH_FORMAT_FETCH_OFF_T " "
           "Bytesleft %" FETCH_FORMAT_FETCH_OFF_T "\n",
           (int)i,
           nread, meta->age, meta->flags, meta->offset, meta->bytesleft);
    i += meta->len;
    fwrite(buffer, 1, nread, save);
  }
  fclose(save);

  websocket_close(fetch);
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if (fetch)
  {
    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);

    /* use the callback style */
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "websocket/2304");
    libtest_debug_config.nohex = 1;
    libtest_debug_config.tracetime = 1;
    fetch_easy_setopt(fetch, FETCHOPT_DEBUGDATA, &libtest_debug_config);
    fetch_easy_setopt(fetch, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = fetch_easy_perform(fetch);
    fprintf(stderr, "fetch_easy_perform() returned %d\n", res);
    if (res == FETCHE_OK)
      websocket(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return res;
}

#else
NO_SUPPORT_BUILT_IN
#endif
