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

/* snprintf.c times a format that uses widths and a '*' argument. This test
   times a commonly used simple format instead: literal text plus %s, a size_t
   and a curl_off_t, with no width or precision. It is the shape of the
   messages curl builds with infof() and similar all over the library, taken
   from a real one in lib/imap.c, so it measures the common case rather than
   the elaborate one. The sink is a caller's buffer, as in snprintf.c. */

static int test_simpleformat(int argc, const char **argv)
{
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;

  curl_off_t loops = 10000000, loop;

  char buffer[256];

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    curl_msnprintf(buffer, sizeof(buffer),
                   "%s: wrote %zu bytes, %" CURL_FORMAT_CURL_OFF_T
                   " bytes are left for transfer\n",
                   "upload", (size_t)4096, (curl_off_t)1048576);
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = loops ? us * 100000 / loops : 0; /* 100 times too big */
  curl_mprintf("Loops:     %" CURL_FORMAT_CURL_OFF_T "\n"
               "Time:      %lld usecs\n"
               "Time/loop: %lld.%0lld ns\n",
               loops,
               (long long)us,
               (long long)hn / 100,
               (long long)hn % 100);
  return 0;
}
