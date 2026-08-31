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

static int test_percent(int argc, const char **argv)
{
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  curl_off_t loops = 2500000, loop;
  unsigned char array[256];
  unsigned int c;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  for(c = 0; c < 256; c++)
    array[c] = (unsigned char)c;

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    char *encoded =
      curl_easy_escape(NULL, (char *)array, (int)sizeof(array));
    if(encoded) {
      char *unesc = NULL;
      int unlen = 0;
      /* now unescape it again */
      unesc = curl_easy_unescape(NULL, encoded, 0, &unlen);
      if(!unesc) {
        curl_mfprintf(stderr, "unexpected unescape error\n");
        return 1;
      }
      curl_free(unesc);
    }
    else {
      curl_mfprintf(stderr, "unexpected escape error\n");
      return 1;
    }
    curl_free(encoded);
  }
  end = curlx_now();
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = loop ? us * 100000 / loops : 0; /* 100 times too big */
  curl_mprintf("Loops:     %" CURL_FORMAT_CURL_OFF_T "\n"
               "Time:      %lld usecs\n"
               "Time/loop: %lld.%0lld ns\n",
               loops,
               (long long)us,
               (long long)hn / 100,
               (long long)hn % 100);
  return 0;
}
