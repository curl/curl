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
#include "unitcheck.h"

#include "speedcheck.h"
#include "urldata.h"

static CURLcode t1606_setup(struct Curl_easy **easy)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return res;
}

static void t1606_stop(struct Curl_easy *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static int runawhile(struct Curl_easy *easy,
                     long time_limit,
                     long speed_limit,
                     curl_off_t speed,
                     int dec)
{
  int counter = 1;
  struct curltime now = {1, 0};
  CURLcode result;
  int finaltime;

  curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, speed_limit);
  curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, time_limit);
  Curl_speedinit(easy);

  do {
    /* fake the current transfer speed */
    easy->progress.current_speed = speed;
    result = Curl_speedcheck(easy, now);
    if(result)
      break;
    /* step the time */
    now.tv_sec = ++counter;
    speed -= dec;
  } while(counter < 100);

  finaltime = (int)(now.tv_sec - 1);

  return finaltime;
}

static CURLcode test_unit1606(const char *arg)
{
  struct Curl_easy *easy;

  UNITTEST_BEGIN(t1606_setup(&easy))

  fail_unless(runawhile(easy, 41, 41, 40, 0) == 41,
              "wrong low speed timeout");
  fail_unless(runawhile(easy, 21, 21, 20, 0) == 21,
              "wrong low speed timeout");
  fail_unless(runawhile(easy, 60, 60, 40, 0) == 60,
              "wrong log speed timeout");
  fail_unless(runawhile(easy, 50, 50, 40, 0) == 50,
              "wrong log speed timeout");
  fail_unless(runawhile(easy, 40, 40, 40, 0) == 99,
              "should not time out");
  fail_unless(runawhile(easy, 10, 50, 100, 2) == 36,
              "bad timeout");

  UNITTEST_END(t1606_stop(easy))
}
