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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <curl/curl.h>

/*
 */
static int test_base64(int argc, const char **argv)
{
  struct timeval start;
  struct timeval end;
  unsigned char array[256];
  unsigned int c;
  int i;
  time_t diff;
  long us;
  long long hn;
  curl_off_t loops = 10000000;

  if(argc > 1) {
    const char *ptr = argv[2];
    curlx_str_number(&ptr, &loops, CURL_OFF_T_MAX);
  }

  for(c = 0; c < 256; c++) {
    array[c] = (unsigned char)c;
  }

  gettimeofday(&start, NULL);
  for(i = 0; i < loops; i++) {
    char *encoded;
    size_t enclen;
    CURLcode rc =
      curlx_base64_encode(array, sizeof(array), &encoded, &enclen);
    if(!rc) {
      unsigned char *recoded = NULL;
      size_t reclen;
      /* now decoded it again */
      rc = curlx_base64_decode(encoded, &recoded, &reclen);
      curlx_free(recoded);
    }
    if(rc) {
      curl_mfprintf(stderr, "unexpected coding error: %d\n", (int)rc);
      return 1;
    }
    curlx_free(encoded);
  }
  gettimeofday(&end, NULL);
  diff = end.tv_sec-start.tv_sec;
  /* how many microseconds */
  us = diff * 1000000 + end.tv_usec-start.tv_usec;
  hn = us*100000/loops; /* 100 times too big */
  curl_mprintf("Loops:     %" CURL_FORMAT_CURL_OFF_T "\n"
               "Time:      %ld usecs\n"
               "Time/loop: %lld.%lld ns\n",
               loops,
               us,
               hn / 100,
               hn % 100);
  return 0;
}
