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

static CURLcode t2412_run(CURLM *multi, CURL *curl,
                          struct curl_slist *headers, long priorities)
{
  CURLcode result = CURLE_OK;
  int running;

  if(headers)
    easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  easy_setopt(curl, CURLOPT_HTTP_PRIO, priorities);

  /* add handle to multi */
  multi_add_handle(multi, curl);

  for(;;) {
    struct timeval interval;
    fd_set rd, wr, exc;
    int maxfd = -99;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    multi_perform(multi, &running);

    abort_on_test_timeout();

    if(!running)
      break; /* done */

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    multi_fdset(multi, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:
  curl_multi_remove_handle(multi, curl);
  return result;
}

static CURLcode test_lib2412(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  CURLM *multi = NULL;
  char target_url[256];
  char dnsentry[256];
  struct curl_slist *slist = NULL, *headers = NULL;
  const char *port = libtest_arg3;
  const char *address = libtest_arg2;

  (void)URL;

  curl_msnprintf(dnsentry, sizeof(dnsentry), "localhost:%s:%s", port, address);
  curl_mprintf("%s\n", dnsentry);
  slist = curl_slist_append(slist, dnsentry);
  if(!slist) {
    curl_mfprintf(stderr, "curl_slist_append() resolve failed\n");
    goto test_cleanup;
  }

  headers = curl_slist_append(NULL, "Priority: custom");
  if(!headers) {
    curl_mfprintf(stderr, "curl_slist_append() headers failed\n");
    goto test_cleanup;
  }

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  easy_init(curl);
  /* specify target */
  curl_msnprintf(target_url, sizeof(target_url),
                 "http://localhost:%s/path/2412", port);
  target_url[sizeof(target_url) - 1] = '\0';
  easy_setopt(curl, CURLOPT_URL, target_url);
  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  /* include headers */
  easy_setopt(curl, CURLOPT_HEADER, 1L);

  easy_setopt(curl, CURLOPT_RESOLVE, slist);

  /* no custom header, highest urgency */
  result = t2412_run(multi, curl, NULL, CURL_HTTP_PRIO_U0);
  if(result)
    goto test_cleanup;
  /* no custom header, urgency 1 and incremental */
  result = t2412_run(multi, curl, NULL, CURL_HTTP_PRIO_U1|CURL_HTTP_PRIO_I);
  if(result)
    goto test_cleanup;
  /* no custom header, default urgency, no Priority: header sent */
  result = t2412_run(multi, curl, NULL, CURL_HTTP_PRIO_NONE);
  if(result)
    goto test_cleanup;
  /* custom header, default urgency, custom Priority: sent */
  result = t2412_run(multi, curl, headers, CURL_HTTP_PRIO_NONE);
  if(result)
    goto test_cleanup;
  /* custom header, low urgency, custom Priority: sent */
  result = t2412_run(multi, curl, headers, CURL_HTTP_PRIO_U7);
  if(result)
    goto test_cleanup;

test_cleanup:

  /* proper cleanup sequence - type PB */
  curl_easy_cleanup(curl);

  curl_slist_free_all(headers);
  curl_slist_free_all(slist);

  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return result;
}
