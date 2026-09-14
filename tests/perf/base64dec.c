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

/* this is 256 bytes using the octets 0-255, base64 encoded */
#define BLOB64                                                          \
  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMD"  \
  "EyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFi"  \
  "Y2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5"  \
  "SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TF"  \
  "xsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19v"  \
  "f4+fr7/P3+/w=="

static int test_base64dec(int argc, const char **argv)
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
    unsigned char *recoded = NULL;
    size_t reclen;
    CURLcode result = curlx_base64_decode(BLOB64, &recoded, &reclen);
    curlx_free(recoded);
    if(result) {
      curl_mfprintf(stderr, "unexpected coding error: %d\n", (int)result);
      return 1;
    }
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
