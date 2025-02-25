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
#include "test.h"

#include "testtrace.h"
#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

#define NUM_HANDLES 4

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl[NUM_HANDLES] = {0};
  int running;
  CURLM *m = NULL;
  int i;
  char target_url[256];
  char dnsentry[256];
  struct curl_slist *slist = NULL;
  char *port = libtest_arg3;
  char *address = libtest_arg2;

  (void)URL;

  msnprintf(dnsentry, sizeof(dnsentry), "localhost:%s:%s",
            port, address);
  printf("%s\n", dnsentry);
  slist = curl_slist_append(slist, dnsentry);
  if(!slist) {
    fprintf(stderr, "curl_slist_append() failed\n");
    goto test_cleanup;
  }

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(m);

  multi_setopt(m, CURLMOPT_MAXCONNECTS, 1L);

  /* get NUM_HANDLES easy handles */
  for(i = 0; i < NUM_HANDLES; i++) {
    /* get an easy handle */
    easy_init(curl[i]);
    /* specify target */
    msnprintf(target_url, sizeof(target_url),
              "https://localhost:%s/path/2502%04i",
              port, i + 1);
    target_url[sizeof(target_url) - 1] = '\0';
    easy_setopt(curl[i], CURLOPT_URL, target_url);
    /* go http2 */
    easy_setopt(curl[i], CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3ONLY);
    easy_setopt(curl[i], CURLOPT_CONNECTTIMEOUT_MS, (long)5000);
    easy_setopt(curl[i], CURLOPT_CAINFO, "./certs/EdelCurlRoot-ca.cacert");
    /* wait for first connection established to see if we can share it */
    easy_setopt(curl[i], CURLOPT_PIPEWAIT, 1L);
    /* go verbose */
    libtest_debug_config.nohex = 1;
    libtest_debug_config.tracetime = 0;
    test_setopt(curl[i], CURLOPT_DEBUGDATA, &libtest_debug_config);
    easy_setopt(curl[i], CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
    easy_setopt(curl[i], CURLOPT_VERBOSE, 1L);
    /* include headers */
    easy_setopt(curl[i], CURLOPT_HEADER, 1L);

    easy_setopt(curl[i], CURLOPT_RESOLVE, slist);
  }

  fprintf(stderr, "Start at URL 0\n");

  for(i = 0; i < NUM_HANDLES; i++) {
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
    wait_ms(1); /* to ensure different end times */
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  for(i = 0; i < NUM_HANDLES; i++) {
    curl_multi_remove_handle(m, curl[i]);
    curl_easy_cleanup(curl[i]);
  }

  curl_slist_free_all(slist);

  curl_multi_cleanup(m);
  curl_global_cleanup();

  return res;
}
