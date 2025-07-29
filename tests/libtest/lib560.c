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

#include "memdebug.h"

/*
 * Simply download an HTTPS file!
 *
 * This test was added after the HTTPS-using-multi-interface with OpenSSL
 * regression of 7.19.1 to hopefully prevent this embarrassing mistake from
 * appearing again... Unfortunately the bug wasn't triggered by this test,
 * which presumably is because the connect to a local server is too
 * fast/different compared to the real/distant servers we saw the bug happen
 * with.
 */
static CURLcode test_lib560(const char *URL)
{
  CURL *http_handle = NULL;
  CURLM *multi_handle = NULL;
  CURLcode res = CURLE_OK;

  int still_running; /* keep number of running handles */

  start_test_timing();

  /*
  ** curl_global_init called indirectly from curl_easy_init.
  */

  easy_init(http_handle);

  /* set options */
  easy_setopt(http_handle, CURLOPT_URL, URL);
  easy_setopt(http_handle, CURLOPT_HEADER, 1L);
  easy_setopt(http_handle, CURLOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(http_handle, CURLOPT_SSL_VERIFYHOST, 0L);

  /* init a multi stack */
  multi_init(multi_handle);

  /* add the individual transfers */
  multi_add_handle(multi_handle, http_handle);

  /* we start some action by calling perform right away */
  multi_perform(multi_handle, &still_running);

  abort_on_test_timeout();

  while(still_running) {
    struct timeval timeout;

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -99;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* get file descriptors from the transfers */
    multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    abort_on_test_timeout();

    /* timeout or readable/writable sockets */
    multi_perform(multi_handle, &still_running);

    abort_on_test_timeout();
  }

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(multi_handle);
  curl_easy_cleanup(http_handle);
  curl_global_cleanup();

  return res;
}
