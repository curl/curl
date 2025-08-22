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

#define WAKEUP_NUM 10

static CURLcode test_lib1564(const char *URL)
{
  CURLM *multi = NULL;
  int numfds;
  int i;
  CURLcode res = CURLE_OK;
  struct curltime time_before_wait, time_after_wait;

  (void)URL;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  /* no wakeup */

  time_before_wait = curlx_now();
  multi_poll(multi, NULL, 0, 1000, &numfds);
  time_after_wait = curlx_now();

  if(curlx_timediff(time_after_wait, time_before_wait) < 500) {
    curl_mfprintf(stderr, "%s:%d curl_multi_poll returned too early\n",
                  __FILE__, __LINE__);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  abort_on_test_timeout();

  /* try a single wakeup */

  res_multi_wakeup(multi);

  time_before_wait = curlx_now();
  multi_poll(multi, NULL, 0, 1000, &numfds);
  time_after_wait = curlx_now();

  if(curlx_timediff(time_after_wait, time_before_wait) > 500) {
    curl_mfprintf(stderr, "%s:%d curl_multi_poll returned too late\n",
                  __FILE__, __LINE__);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  abort_on_test_timeout();

  /* previous wakeup should not wake up this */

  time_before_wait = curlx_now();
  multi_poll(multi, NULL, 0, 1000, &numfds);
  time_after_wait = curlx_now();

  if(curlx_timediff(time_after_wait, time_before_wait) < 500) {
    curl_mfprintf(stderr, "%s:%d curl_multi_poll returned too early\n",
                  __FILE__, __LINE__);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  abort_on_test_timeout();

  /* try lots of wakeup */

  for(i = 0; i < WAKEUP_NUM; ++i)
    res_multi_wakeup(multi);

  time_before_wait = curlx_now();
  multi_poll(multi, NULL, 0, 1000, &numfds);
  time_after_wait = curlx_now();

  if(curlx_timediff(time_after_wait, time_before_wait) > 500) {
    curl_mfprintf(stderr, "%s:%d curl_multi_poll returned too late\n",
                  __FILE__, __LINE__);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  abort_on_test_timeout();

  /* Even lots of previous wakeups should not wake up this. */

  time_before_wait = curlx_now();
  multi_poll(multi, NULL, 0, 1000, &numfds);
  time_after_wait = curlx_now();

  if(curlx_timediff(time_after_wait, time_before_wait) < 500) {
    curl_mfprintf(stderr, "%s:%d curl_multi_poll returned too early\n",
                  __FILE__, __LINE__);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  abort_on_test_timeout();

test_cleanup:

  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return res;
}
