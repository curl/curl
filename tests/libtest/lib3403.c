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

#include "testtrace.h"

struct t3403_state {
  CURL *curl;
  int errors;
  int write_calls;
  int xfer_while_recv_paused;
  int checked_unpaused;
  int checked_send_paused;
};

static int check_pause_state(struct t3403_state *st, long expected,
                             const char *label)
{
  long state = -1;
  CURLcode result = curl_easy_getinfo(st->curl, CURLINFO_PAUSE_STATE, &state);

  if(result != CURLE_OK) {
    curl_mfprintf(stderr, "%s: getinfo failed (%d)\n", label, (int)result);
    st->errors++;
    return 1;
  }
  if(state != expected) {
    curl_mfprintf(stderr, "%s: expected %ld, got %ld\n",
                  label, expected, state);
    st->errors++;
    return 1;
  }
  curl_mfprintf(stderr, "%s: pause state %ld OK\n", label, state);
  return 0;
}

static int t3403_xferinfo(void *userp,
                           curl_off_t dltotal,
                           curl_off_t dlnow,
                           curl_off_t ultotal,
                           curl_off_t ulnow)
{
  struct t3403_state *st = (struct t3403_state *)userp;

  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;

  if(st->write_calls == 1 && !st->xfer_while_recv_paused) {
    st->xfer_while_recv_paused = 1;
    check_pause_state(st, CURLPAUSE_RECV, "recv paused via write callback");
    curl_easy_pause(st->curl, CURLPAUSE_CONT);
    return 0;
  }

  if(st->write_calls >= 2 && !st->checked_unpaused) {
    st->checked_unpaused = 1;
    check_pause_state(st, 0, "unpaused after CONT");
    curl_easy_pause(st->curl, CURLPAUSE_SEND);
    return 0;
  }

  if(st->checked_unpaused && !st->checked_send_paused) {
    st->checked_send_paused = 1;
    check_pause_state(st, CURLPAUSE_SEND, "send paused explicitly");
    curl_easy_pause(st->curl, CURLPAUSE_CONT);
  }

  return 0;
}

static size_t t3403_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t3403_state *st = (struct t3403_state *)userp;
  size_t len = size * nmemb;

  st->write_calls++;
  if(st->write_calls == 1) {
    if(len)
      curl_mprintf("Got bytes but pausing!\n");
    return CURL_WRITEFUNC_PAUSE;
  }

  fwrite(ptr, size, nmemb, stdout);
  return len;
}

static CURLcode test_lib3403(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  struct t3403_state st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);
  st.curl = curl;

  check_pause_state(&st, 0, "before transfer");

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3403_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &st);
  easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, t3403_xferinfo);
  easy_setopt(curl, CURLOPT_XFERINFODATA, &st);
  easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  easy_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  result = curl_easy_perform(curl);

  check_pause_state(&st, 0, "after transfer");

  if(!st.xfer_while_recv_paused || !st.checked_unpaused ||
     !st.checked_send_paused) {
    curl_mfprintf(stderr, "missing pause state checks "
                  "(recv=%d unpaused=%d send=%d)\n",
                  st.xfer_while_recv_paused, st.checked_unpaused,
                  st.checked_send_paused);
    st.errors++;
  }

  if(st.errors)
    result = TEST_ERR_FAILURE;

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
