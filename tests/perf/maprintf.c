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

/* snprintf.c times curl_msnprintf() into a caller's buffer. This test times
   curl_maprintf(), which allocates and returns the result, because that is
   the path libcurl itself uses to assemble request lines and headers, and its
   per-byte cost differs from the fixed-buffer one. The format is a request
   header block: literal text, %s, and a curl_off_t Content-Length, the shape
   lib/http.c builds on every request that has a body. The allocation and the
   free are inside the timed loop on purpose, because a caller pays them. */

static int test_maprintf(int argc, const char **argv)
{
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;

  curl_off_t loops = 10000000, loop;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    char *s = curl_maprintf("%s %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n",
                            "POST", "/path/to/resource", "example.com",
                            (curl_off_t)4096);
    curl_free(s);
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
