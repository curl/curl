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
#include "curlcheck.h"

#include "timeval.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

struct a {
  struct curltime first;
  struct curltime second;
  time_t result;
};

UNITTEST_START
{
  struct a tests[] = {
    { {36762, 8345 }, {36761, 995926 }, 13 },
    { {36761, 995926 }, {36762, 8345 }, -13 },
    { {36761, 995926 }, {0, 0}, 36761995 },
    { {0, 0}, {36761, 995926 }, -36761995 },
  };
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
    timediff_t result = Curl_timediff(tests[i].first, tests[i].second);
    if(result != tests[i].result) {
      printf("%ld.%06u to %ld.%06u got %d, but expected %ld\n",
             (long)tests[i].first.tv_sec,
             tests[i].first.tv_usec,
             (long)tests[i].second.tv_sec,
             tests[i].second.tv_usec,
             (int)result,
             (long)tests[i].result);
      fail("unexpected result!");
    }
  }
}
UNITTEST_STOP
