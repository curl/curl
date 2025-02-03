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
 * are also available at https://fetch.se/docs/copyright.html.
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
#include "fetchcheck.h"

#include "speedcheck.h"
#include "urldata.h"

static struct Fetch_easy *easy;

static FETCHcode unit_setup(void)
{
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);
  easy = fetch_easy_init();
  if (!easy)
  {
    fetch_global_cleanup();
    return FETCHE_OUT_OF_MEMORY;
  }
  return res;
}

static void unit_stop(void)
{
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
}

static int runawhile(long time_limit,
                     long speed_limit,
                     fetch_off_t speed,
                     int dec)
{
  int counter = 1;
  struct fetchtime now = {1, 0};
  FETCHcode result;
  int finaltime;

  fetch_easy_setopt(easy, FETCHOPT_LOW_SPEED_LIMIT, speed_limit);
  fetch_easy_setopt(easy, FETCHOPT_LOW_SPEED_TIME, time_limit);
  Fetch_speedinit(easy);

  do
  {
    /* fake the current transfer speed */
    easy->progress.current_speed = speed;
    result = Fetch_speedcheck(easy, now);
    if (result)
      break;
    /* step the time */
    now.tv_sec = ++counter;
    speed -= dec;
  } while (counter < 100);

  finaltime = (int)(now.tv_sec - 1);

  return finaltime;
}

UNITTEST_START
fail_unless(runawhile(41, 41, 40, 0) == 41,
            "wrong low speed timeout");
fail_unless(runawhile(21, 21, 20, 0) == 21,
            "wrong low speed timeout");
fail_unless(runawhile(60, 60, 40, 0) == 60,
            "wrong log speed timeout");
fail_unless(runawhile(50, 50, 40, 0) == 50,
            "wrong log speed timeout");
fail_unless(runawhile(40, 40, 40, 0) == 99,
            "should not time out");
fail_unless(runawhile(10, 50, 100, 2) == 36,
            "bad timeout");
UNITTEST_STOP
