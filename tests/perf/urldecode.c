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

/* every octet 0-255 URL encoded (or not). In two parts to avoid compilers
   complaining */
#define URLENCODED1                                                     \
  "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15"  \
  "%16%17%18%19%1A%1B%1C%1D%1E%1F%20%21%22%23%24%25%26%27%28%29%2A%2B"  \
  "%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
  "%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F%80%81%82%83" \
  "%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F%90%91%92%93%94%95%96%97%98%99"

#define URLENCODED2                                                     \
  "%9A%9B%9C%9D%9E%9F%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF"  \
  "%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%BA%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5"  \
  "%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB"  \
  "%DC%DD%DE%DF%E0%E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF%F0%F1"  \
  "%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE%FF"

static int test_urldecode(int argc, const char **argv)
{
  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;
  curl_off_t loops = 2500000, loop;
  char buffer[1024];
  int len;

  if(argc > 1) {
    const char *ptr = argv[1];
    curl_off_t num;
    if(!curlx_str_number(&ptr, &num, CURL_OFF_T_MAX) && !*ptr)
      loops = num;
  }

  len = curl_msnprintf(buffer, sizeof(buffer),
                       "%s%s", URLENCODED1, URLENCODED2);

  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
    char *unesc = NULL;
    int unlen = 0;
    /* now unescape it again */
    unesc = curl_easy_unescape(NULL, buffer, len, &unlen);
    if(!unesc) {
      curl_mfprintf(stderr, "unexpected unescape error\n");
      return 1;
    }
    curl_free(unesc);
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
