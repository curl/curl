/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curlcheck.h"

#include "urldata.h"
#include "progress.h"

static int usec_magnitude = 1000000;

static bool unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

static bool usec_matches_seconds(time_t time_usec, int expected_seconds)
{
  int time_sec = (int)(time_usec / usec_magnitude);
  bool same = (time_sec == expected_seconds);
  fprintf(stderr, "is %d us same as %d seconds? %s\n",
          (int)time_usec, expected_seconds,
          same?"Yes":"No");
  return same;
}

UNITTEST_START
  struct Curl_easy data;
  struct curltime now = Curl_tvnow();

  data.progress.t_starttransfer = 0;
  data.progress.t_redirect = 0;

  /*
  * Set the startsingle time to a second ago. This time is used by
  * Curl_pgrsTime to calculate how much time the events takes.
  * t_starttransfer should be updated to reflect the difference from this time
  * when `Curl_pgrsTime is invoked.
  */
  data.progress.t_startsingle.tv_sec = now.tv_sec - 1;
  data.progress.t_startsingle.tv_usec = now.tv_usec;

  Curl_pgrsTime(&data, TIMER_STARTTRANSFER);

  fail_unless(usec_matches_seconds(data.progress.t_starttransfer, 1),
              "about 1 second should have passed");

  /*
  * Update the startsingle time to a second ago to simulate another second has
  * passed.
  * Now t_starttransfer should not be changed, as t_starttransfer has already
  * occurred and another invocation of `Curl_pgrsTime` for TIMER_STARTTRANSFER
  * is superfluous.
  */
  data.progress.t_startsingle.tv_sec = now.tv_sec - 2;
  data.progress.t_startsingle.tv_usec = now.tv_usec;

  Curl_pgrsTime(&data, TIMER_STARTTRANSFER);

  fail_unless(usec_matches_seconds(data.progress.t_starttransfer, 1),
              "about 1 second should have passed");

  /*
  * Simulate what happens after a redirect has occurred.
  *
  * Since the value of t_starttransfer is set to the value from the first
  * request, it should be updated when a transfer occurs such that
  * t_starttransfer is the starttransfer time of the redirect request.
  */
  data.progress.t_startsingle.tv_sec = now.tv_sec - 3;
  data.progress.t_startsingle.tv_usec = now.tv_usec;
  data.progress.t_redirect = data.progress.t_starttransfer + 1;

  Curl_pgrsTime(&data, TIMER_STARTTRANSFER);

  fail_unless(usec_matches_seconds(data.progress.t_starttransfer, 3),
              "about 3 second should have passed");
UNITTEST_STOP
