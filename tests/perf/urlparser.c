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

static const int options[] = {
  CURLU_DEFAULT_PORT,
  CURLU_NO_DEFAULT_PORT,
  CURLU_DEFAULT_SCHEME,
  CURLU_NON_SUPPORT_SCHEME,
  CURLU_ALLOW_SPACE,
  CURLU_GUESS_SCHEME,
  CURLU_PATH_AS_IS,
  CURLU_DISALLOW_USER
};

#define MAX_URLS 200000

static char *urls[MAX_URLS];

/*
 * Read many URLS from a given file.
 * Parse them with all listed option combinations
 */
static int test_urlparser(int argc, const char **argv)
{
  size_t o;
  size_t count = 0;
  size_t ecount = 0; /* errors */
  struct timeval start;
  struct timeval end;
  time_t diff;
  long us;
  long long hn;
  int fd;
  char *buffer;
  size_t i;
  int loop;
  size_t nsize;
  size_t nurls = 0; /* number of URLs */
  struct stat info;
  curl_off_t iterations = 10;
  char *p;
  CURLU *uh;

  if(argc < 2) {
    curl_mfprintf(stderr, "%s <URL file> [iterations]\n", argv[0]);
    return 2;
  }
  if(argc > 2) {
    const char *ptr = argv[2];
    curlx_str_number(&ptr, &iterations, 100000);
  }

  fd = curlx_open(argv[1], O_RDONLY);
  if(fd == -1) {
    curl_mfprintf(stderr, "Can't open %s, exiting\n", argv[1]);
    return 3;
  }

  if(curlx_fstat(fd, &info) == -1) {
    curl_mfprintf(stderr, "Can't open %s, exiting\n", argv[1]);
    return 3;
  }

  nsize = info.st_size;

  buffer = curlx_malloc(nsize + 1);
  if(!buffer) {
    curl_mfprintf(stderr, "Can't malloc the buffer\n");
    return 4;
  }

  if((ssize_t)nsize != read(fd, buffer, nsize)) {
    curl_mfprintf(stderr, "Can't load the file\n");
    return 4;
  }
  buffer[nsize] = 0;
  p = buffer;
  while(1) {
    if(nurls >= MAX_URLS) {
      curl_mfprintf(stderr,
                    "TOO many URLs in file, rebuild with higher max\n");
      return 4;
    }
    urls[nurls++] = p;
    p = strchr(p, '\n');
    if(!p)
      break;
    *p = '\0';
    p++;
  }
  curl_mprintf("Found %zu URLs to test for %" CURL_FORMAT_CURL_OFF_T
               " iterations (%zu variations)\n",
               nurls, iterations, CURL_ARRAYSIZE(options));

  uh = curl_url();
  gettimeofday(&start, NULL);
  for(loop = 0; loop < iterations; loop++) {
    for(i = 0 ; i < nurls; i++) {
      for(o = 0; o < CURL_ARRAYSIZE(options); o++) {
        CURLUcode hcode =
          curl_url_set(uh, CURLUPART_URL, urls[i], options[o]);
        count++;
        if(hcode) {
#if 0
          curl_mfprintf(stderr, "Failed [%u]: %s\n", (int)hcode, buffer);
#endif
          ecount++;
        }
      }
    }
  }
  gettimeofday(&end, NULL);
  curl_url_cleanup(uh);
  diff = end.tv_sec-start.tv_sec;
  /* how many microseconds */
  us = diff * 1000000 + end.tv_usec-start.tv_usec;
  hn = us*100000/count; /* 100 times too big */
  curl_mprintf("URLs:     %zu\n"
               "Time:     %ld usecs\n"
               "Time/URL: %lld.%lld ns\n"
               "URLs/sec: %lu\n"
               "Errors:   %zu\n",
               count,
               us,
               hn / 100,
               hn % 100,
               (count * 1000000) / us,
               ecount);
  return 0;
}
