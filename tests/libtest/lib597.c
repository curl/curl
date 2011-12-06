/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 5 * 1000

/*
 * Test case for below scenario:
 *   - Connect to an FTP server using CONNECT_ONLY option
 *   - transfer some files with re-using the connection (omitted in test case)
 *   - Disconnect from FTP server with sending QUIT command
 *
 * The test case originated for verifying CONNECT_ONLY option shall not
 * block after protocol connect is done, but it returns the message
 * with function curl_multi_info_read().
 */

enum {
  CONNECT_ONLY_PHASE = 0,
  QUIT_PHASE,
  LAST_PHASE
};

int test(char *URL)
{
  CURL *easy = NULL;
  CURLM *multi = NULL;
  int res = 0;
  int running;
  int msgs_left;
  int phase;
  CURLMsg *msg;

  start_test_timing();

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    return res;
  }

  easy_init(easy);

  multi_init(multi);

  for (phase = CONNECT_ONLY_PHASE; phase < LAST_PHASE; ++phase) {
    /* go verbose */
    easy_setopt(easy, CURLOPT_VERBOSE, 1L);

    /* specify target */
    easy_setopt(easy, CURLOPT_URL, URL);

    /* enable 'CONNECT_ONLY' option when in connect phase */
    if (phase == CONNECT_ONLY_PHASE)
      easy_setopt(easy, CURLOPT_CONNECT_ONLY, 1L);

    /* enable 'NOBODY' option to send 'QUIT' command in quit phase */
    if (phase == QUIT_PHASE) {
      easy_setopt(easy, CURLOPT_CONNECT_ONLY, 0L);
      easy_setopt(easy, CURLOPT_NOBODY, 1L);
      easy_setopt(easy, CURLOPT_FORBID_REUSE, 1L);
    }

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
        interval.tv_sec = timeout/1000;
        interval.tv_usec = (timeout%1000)*1000;
      }
      else {
        interval.tv_sec = TEST_HANG_TIMEOUT/1000+1;
        interval.tv_usec = 0;
      }

      select_test(maxfd+1, &fdread, &fdwrite, &fdexcep, &interval);

      abort_on_test_timeout();
    }

    msg = curl_multi_info_read(multi, &msgs_left);
    if(msg)
      res = msg->data.result;

    multi_remove_handle(multi, easy);
  }

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  return res;
}
