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

/* Unpause from within the debug callback while paused output is being
   replayed. */

struct t3235_status {
  CURL *curl;
  int writes;  /* write callback invocations */
  int nested;  /* nested pause + unpause done */
};

static size_t t3235_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userp)
{
  struct t3235_status *st = (struct t3235_status *)userp;
  size_t len = size * nmemb;
  st->writes++;
  /* pause on the first delivery and on its replay */
  if(st->writes <= 2)
    return CURL_WRITEFUNC_PAUSE;
  fwrite(ptr, size, nmemb, stdout);
  return len;
}

static int t3235_debug_cb(CURL *curl, curl_infotype type, char *data,
                          size_t size, void *userp)
{
  struct t3235_status *st = (struct t3235_status *)userp;
  static const char want[] = "PAUSE requested";
  (void)curl;
  if((type == CURLINFO_TEXT) && (st->writes == 2) && !st->nested &&
     (size >= sizeof(want) - 1)) {
    size_t i;
    for(i = 0; i + sizeof(want) - 1 <= size; i++) {
      if(!memcmp(&data[i], want, sizeof(want) - 1)) {
        st->nested = 1;
        curl_easy_pause(st->curl, CURLPAUSE_RECV);
        curl_easy_pause(st->curl, CURLPAUSE_CONT);
        break;
      }
    }
  }
  return 0;
}

static CURLcode test_lib3235(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  struct t3235_status st;
  int running = 1;
  int unpaused = 0;
  int numfds;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);
  curl_global_trace("write");

  easy_init(curl);
  st.curl = curl;

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3235_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &st);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, t3235_debug_cb);
  easy_setopt(curl, CURLOPT_DEBUGDATA, &st);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  multi_init(multi);
  multi_add_handle(multi, curl);

  while(running) {
    multi_perform(multi, &running);
    abort_on_test_timeout();
    if((st.writes == 1) && !unpaused) {
      /* the body is buffered, unpause to replay it */
      unpaused = 1;
      curl_easy_pause(curl, CURLPAUSE_CONT);
    }
    if(running)
      multi_poll(multi, NULL, 0, 100, &numfds);
    abort_on_test_timeout();
  }

  if(!st.nested) {
    curl_mfprintf(stderr, "nested unpause was never exercised\n");
    result = TEST_ERR_FAILURE;
  }

test_cleanup:

  curl_multi_remove_handle(multi, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return result;
}
