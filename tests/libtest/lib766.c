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

static int sockopt_766(void *clientp,
                       curl_socket_t curlfd,
                       curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  if(purpose == CURLSOCKTYPE_ACCEPT) {
    curl_mfprintf(stderr,
                  "Return error from CURLOPT_SOCKOPTFUNCTION callback\n");
    return 1; /* force error */
  }
  return 0;
}

static CURLcode test_lib766(const char *URL)
{
  CURL *easy = NULL;
  CURLM *multi = NULL;
  CURLcode res = CURLE_OK;
  int running;
  int msgs_left;
  CURLMsg *msg;

  start_test_timing();

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    return res;
  }

  easy_init(easy);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_FTPPORT, "-");
  easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, sockopt_766);

  multi_init(multi);

  multi_add_handle(multi, easy);

  for(;;) {
    struct timeval interval;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    long timeout = -99;
    int maxfd = -99;

    multi_perform(multi, &running);

    abort_on_test_timeout();

    if(!running)
      break; /* done */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    multi_timeout(multi, &timeout);

    /* At this point, timeout is guaranteed to be greater or equal than -1. */

    if(timeout != -1L) {
      int itimeout;
#if LONG_MAX > INT_MAX
      itimeout = (timeout > (long)INT_MAX) ? INT_MAX : (int)timeout;
#else
      itimeout = (int)timeout;
#endif
      interval.tv_sec = itimeout/1000;
      interval.tv_usec = (itimeout%1000)*1000;
    }
    else {
      interval.tv_sec = 0;
      interval.tv_usec = 100000L; /* 100 ms */
    }

    select_test(maxfd + 1, &fdread, &fdwrite, &fdexcep, &interval);

    abort_on_test_timeout();
  }

  msg = curl_multi_info_read(multi, &msgs_left);
  if(msg)
    res = msg->data.result;

test_cleanup:

  curl_multi_cleanup(multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  return res;
}
