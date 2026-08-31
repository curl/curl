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

/*
 * Read many URLs from a given file.
 * Parse them with all listed option combinations
 */
static int test_urlparser(int argc, const char **argv)
{
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

  static char *urls[20000];

  struct curltime start;
  struct curltime end;
  timediff_t us;
  long long hn;

  curl_off_t loops = 10, loop;

  int ret;
  size_t o;
  size_t count = 0;
  size_t ecount = 0; /* errors */
  int fd;
  char *buffer = NULL;
  size_t i;
  size_t nsize;
  ssize_t nread;
  size_t nurls = 0; /* number of URLs */
  curlx_struct_stat info;
  char *p;
  CURLU *uh;

  if(argc < 2) {
    curl_mfprintf(stderr, "%s <URL file> [iterations]\n", argv[0]);
    return 2;
  }
  if(argc > 2) {
    const char *ptr = argv[2];
    curlx_str_number(&ptr, &loops, 100000);
  }

  fd = curlx_open(argv[1], O_RDONLY);
  if(fd == -1) {
    curl_mfprintf(stderr, "Cannot open %s, exiting\n", argv[1]);
    return 3;
  }

  if(curlx_fstat(fd, &info) == -1) {
    curlx_close(fd);
    curl_mfprintf(stderr, "Cannot open %s, exiting\n", argv[1]);
    return 3;
  }

  ret = 4;

  nsize = (size_t)info.st_size;

  buffer = curlx_malloc(nsize + 1);
  if(!buffer) {
    curlx_close(fd);
    curl_mfprintf(stderr, "Cannot malloc the buffer\n");
    goto cleanup;
  }

  nread = read(fd, buffer, nsize);
  curlx_close(fd);
  if(nread != (ssize_t)nsize) {
    curl_mfprintf(stderr, "Cannot load the file\n");
    goto cleanup;
  }

  buffer[nsize] = 0;
  p = buffer;
  while(1) {
    if(nurls >= CURL_ARRAYSIZE(urls)) {
      curl_mfprintf(stderr,
                    "TOO many URLs in file, rebuild with higher max\n");
      goto cleanup;
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
               nurls, loops, CURL_ARRAYSIZE(options));

  uh = curl_url();
  start = curlx_now();
  for(loop = 0; loop < loops; loop++) {
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
  end = curlx_now();
  curl_url_cleanup(uh);
  us = curlx_timediff_us(end, start); /* how many microseconds */
  hn = count ? us * 100000 / count : 0; /* 100 times too big */
  curl_mprintf("URLs:     %zu\n"
               "Time:     %ld usecs\n"
               "Time/URL: %lld.%lld ns\n"
               "URLs/sec: %lld\n"
               "Errors:   %zu\n",
               count,
               (long)us,
               (long long)hn / 100,
               (long long)hn % 100,
               us ? (long long)(count * 1000000) / us : 0,
               ecount);

  ret = 0;

cleanup:

  curlx_free(buffer);

  return ret;
}
