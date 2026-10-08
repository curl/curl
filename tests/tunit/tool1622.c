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
#include "tool_progress.h"

static CURLcode test_tool1622(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  char buffer[9];
  curl_off_t secs;
  int i;
  static const curl_off_t check[] = {
    /* bytes to check */
    131072,
    12645826,
    1073741824,
    12938588979,
    1099445657078333,
    0 /* end of list */
  };
  struct exactcase {
    curl_off_t value;
    const char *output;
  };
  static const struct exactcase timecases[] = {
    { 0, "        " },
    { 1, "00:00:01" },
    { 524287, "  6d 01h" },
    { 134217727, " 51m 23d" },
    { 4294967295, "    136y" },
    { 4398046511103, " >99999y" },
    { 0, NULL }
  };
  static const struct exactcase datacases[] = {
    { 0, "    0" },
    { 99999, "99999" },
    { 100000, "97.6k" },
    { 131072, " 128k" },
    { 12645826, "12.0M" },
    { 1099445657078333, " 999T" },
    { 0, NULL }
  };

  puts("timebuf");
  for(i = 0, secs = 0; i < 63; i++) {
    timebuf(buffer, sizeof(buffer), secs);
    curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
    fail_unless(strlen(buffer) == 8, "timebuf output width");
    secs *= 2;
    secs++;
  }
  puts("max5data");
  for(i = 0, secs = 0; i < 63; i++) {
    max5data(secs, buffer, sizeof(buffer));
    curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
    fail_unless(strlen(buffer) == 5, "max5data output width");
    secs *= 2;
    secs++;
  }
  for(i = 0; check[i]; i++) {
    secs = check[i];
    max5data(secs, buffer, sizeof(buffer));
    curl_mprintf("%20" FMT_OFF_T " - %s\n", secs, buffer);
    fail_unless(strlen(buffer) == 5, "max5data check output width");
  }
  for(i = 0; timecases[i].output; i++) {
    timebuf(buffer, sizeof(buffer), timecases[i].value);
    fail_unless(!strcmp(buffer, timecases[i].output), timecases[i].output);
  }
  for(i = 0; datacases[i].output; i++) {
    max5data(datacases[i].value, buffer, sizeof(buffer));
    fail_unless(!strcmp(buffer, datacases[i].output), datacases[i].output);
  }

  UNITTEST_END_SIMPLE
}
