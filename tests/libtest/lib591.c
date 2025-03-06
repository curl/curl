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

/* lib591 is used for test cases 591, 592, 593 and 594 */

#include <limits.h>

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

CURLcode test(char *URL)
{
  CURL *easy = NULL;
  CURLM *multi = NULL;
  CURLcode res = CURLE_OK;
  int running;
  int msgs_left;
  CURLMsg *msg;
  FILE *upload = NULL;

  start_test_timing();

  upload = fopen(libtest_arg3, "rb");
  if(!upload) {
    fprintf(stderr, "fopen() failed with error (%d) %s\n",
            errno, strerror(errno));
    fprintf(stderr, "Error opening file '%s'\n", libtest_arg3);
    return TEST_ERR_FOPEN;
  }

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fclose(upload);
    return res;
  }

  easy_init(easy);

  /* go verbose */
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  /* specify target */
  easy_setopt(easy, CURLOPT_URL, URL);

  /* enable uploading */
  easy_setopt(easy, CURLOPT_UPLOAD, 1L);

  /* data pointer for the file read function */
  easy_setopt(easy, CURLOPT_READDATA, upload);

  /* use active mode FTP */
  easy_setopt(easy, CURLOPT_FTPPORT, "-");

  /* server connection timeout */
  easy_setopt(easy, CURLOPT_ACCEPTTIMEOUT_MS,
              strtol(libtest_arg2, NULL, 10)*1000);

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

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  /* close the local file */
  fclose(upload);

  return res;
}
