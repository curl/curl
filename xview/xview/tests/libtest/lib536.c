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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

static int perform(CURLM *multi)
{
  int handles;
  fd_set fdread, fdwrite, fdexcep;
  int res = 0;

  for(;;) {
    struct timeval interval;
    int maxfd = -99;

    interval.tv_sec = 0;
    interval.tv_usec = 100000L; /* 100 ms */

    res_multi_perform(multi, &handles);
    if(res)
      return res;

    res_test_timedout();
    if(res)
      return res;

    if(!handles)
      break; /* done */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    res_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    if(res)
      return res;

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    res_select_test(maxfd+1, &fdread, &fdwrite, &fdexcep, &interval);
    if(res)
      return res;

    res_test_timedout();
    if(res)
      return res;
  }

  return 0; /* success */
}

int test(char *URL)
{
  CURLM *multi = NULL;
  CURL *easy = NULL;
  int res = 0;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  easy_init(easy);

  multi_setopt(multi, CURLMOPT_PIPELINING, 1L);

  easy_setopt(easy, CURLOPT_WRITEFUNCTION, fwrite);
  easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
  easy_setopt(easy, CURLOPT_URL, URL);

  res_multi_add_handle(multi, easy);
  if(res) {
    printf("curl_multi_add_handle() 1 failed\n");
    goto test_cleanup;
  }

  res = perform(multi);
  if(res) {
    printf("retrieve 1 failed\n");
    goto test_cleanup;
  }

  curl_multi_remove_handle(multi, easy);

  curl_easy_reset(easy);

  easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
  easy_setopt(easy, CURLOPT_URL, libtest_arg2);

  res_multi_add_handle(multi, easy);
  if(res) {
    printf("curl_multi_add_handle() 2 failed\n");
    goto test_cleanup;
  }

  res = perform(multi);
  if(res) {
    printf("retrieve 2 failed\n");
    goto test_cleanup;
  }

  curl_multi_remove_handle(multi, easy);

test_cleanup:

  /* undocumented cleanup sequence - type UB */

  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  printf("Finished!\n");

  return res;
}
