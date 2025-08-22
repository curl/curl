/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing <linus@haxx.se>
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

#include "memdebug.h"

static CURLcode test_lib1506(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl[NUM_HANDLES] = {0};
  int running;
  CURLM *m = NULL;
  size_t i;
  char target_url[256];
  char dnsentry[256];
  struct curl_slist *slist = NULL, *slist2;
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;

  (void)URL;

  /* Create fake DNS entries for serverX.example.com for all handles */
  for(i = 0; i < CURL_ARRAYSIZE(curl); i++) {
    curl_msnprintf(dnsentry, sizeof(dnsentry), "server%zu.example.com:%s:%s",
                   i + 1, port, address);
    curl_mprintf("%s\n", dnsentry);
    slist2 = curl_slist_append(slist, dnsentry);
    if(!slist2) {
      curl_mfprintf(stderr, "curl_slist_append() failed\n");
      goto test_cleanup;
    }
    slist = slist2;
  }

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(m);

  multi_setopt(m, CURLMOPT_MAXCONNECTS, 3L);

  /* get each easy handle */
  for(i = 0; i < CURL_ARRAYSIZE(curl); i++) {
    /* get an easy handle */
    easy_init(curl[i]);
    /* specify target */
    curl_msnprintf(target_url, sizeof(target_url),
                   "http://server%zu.example.com:%s/path/1506%04zu",
                   i + 1, port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(curl[i], CURLOPT_URL, target_url);
    /* go verbose */
    easy_setopt(curl[i], CURLOPT_VERBOSE, 1L);
    /* include headers */
    easy_setopt(curl[i], CURLOPT_HEADER, 1L);

    easy_setopt(curl[i], CURLOPT_RESOLVE, slist);
  }

  curl_mfprintf(stderr, "Start at URL 0\n");

  for(i = 0; i < CURL_ARRAYSIZE(curl); i++) {
    /* add handle to multi */
    multi_add_handle(m, curl[i]);

    for(;;) {
      struct timeval interval;
      fd_set rd, wr, exc;
      int maxfd = -99;

      interval.tv_sec = 1;
      interval.tv_usec = 0;

      multi_perform(m, &running);

      abort_on_test_timeout();

      if(!running)
        break; /* done */

      FD_ZERO(&rd);
      FD_ZERO(&wr);
      FD_ZERO(&exc);

      multi_fdset(m, &rd, &wr, &exc, &maxfd);

      /* At this point, maxfd is guaranteed to be greater or equal than -1. */

      select_test(maxfd + 1, &rd, &wr, &exc, &interval);

      abort_on_test_timeout();
    }
    curlx_wait_ms(1); /* to ensure different end times */
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  for(i = 0; i < CURL_ARRAYSIZE(curl); i++) {
    curl_multi_remove_handle(m, curl[i]);
    curl_easy_cleanup(curl[i]);
  }

  curl_slist_free_all(slist);

  curl_multi_cleanup(m);
  curl_global_cleanup();

  return res;
}
