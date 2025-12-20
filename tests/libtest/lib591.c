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
/* lib591 is used for test cases 591, 592, 593 and 594 */

#include "first.h"

static CURLcode test_lib591(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  int running;
  int msgs_left;
  CURLMsg *msg;
  FILE *upload = NULL;
  curl_off_t accept_timeout;

  if(curlx_str_number(&libtest_arg2, &accept_timeout, 65535))
    return TEST_ERR_MAJOR_BAD;

  start_test_timing();

  upload = curlx_fopen(libtest_arg3, "rb");
  if(!upload) {
    char errbuf[STRERROR_LEN];
    curl_mfprintf(stderr, "fopen() failed with error (%d) %s\n",
                  errno, curlx_strerror(errno, errbuf, sizeof(errbuf)));
    curl_mfprintf(stderr, "Error opening file '%s'\n", libtest_arg3);
    return TEST_ERR_FOPEN;
  }

  res_global_init(CURL_GLOBAL_ALL);
  if(result) {
    curlx_fclose(upload);
    return result;
  }

  easy_init(curl);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* enable uploading */
  easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  /* data pointer for the file read function */
  easy_setopt(curl, CURLOPT_READDATA, upload);

  /* use active mode FTP */
  easy_setopt(curl, CURLOPT_FTPPORT, "-");

  /* server connection timeout */
  easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, (long)(accept_timeout * 1000));

  multi_init(multi);

  multi_add_handle(multi, curl);

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
      interval.tv_sec = itimeout / 1000;
      interval.tv_usec = (itimeout % 1000) * 1000;
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
    result = msg->data.result;

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(multi);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  /* close the local file */
  curlx_fclose(upload);

  return result;
}
