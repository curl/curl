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

/* Replay a stored-block gzip response while nested unpause is requested
   from the debug callback. The pause writer must not replay its raw bytes
   from a nested flush while its outer flush is still using them. */

struct t3236_status {
  CURL *curl;
  int writes;  /* write callback invocations */
  int pauses;  /* body callback pauses */
  int nested;  /* nested pause + unpause done */
  int raw_buffered; /* at least 4096 compressed bytes waiting for replay */
  int header_paused;
  int header_unpaused;
  int body_unpaused;
  CURLcode nested_result;
  CURLcode header_pause_result;
};

static size_t t3236_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userp)
{
  struct t3236_status *st = (struct t3236_status *)userp;
  size_t len = size * nmemb;
  st->writes++;
  /* Accept a short body delivery that may follow the final header in one
     socket read. Pause twice only once we have a full decoder-sized write. */
  if(st->pauses < 2 && len >= 4000) {
    st->pauses++;
    return CURL_WRITEFUNC_PAUSE;
  }
  fwrite(ptr, size, nmemb, stdout);
  return len;
}

static size_t t3236_header_cb(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  struct t3236_status *st = (struct t3236_status *)userp;
  size_t len = size * nmemb;

  /* Pause receiving while sws finishes its 20-byte writes. The next body
     read can then contain enough gzip input to leave raw bytes buffered at
     the pause writer. Accept the header bytes before returning. */
  if(!st->header_paused && len == 2 && ptr[0] == '\r' && ptr[1] == '\n') {
    st->header_paused = 1;
    st->header_pause_result = curl_easy_pause(st->curl, CURLPAUSE_RECV);
  }
  return len;
}

static int t3236_debug_cb(CURL *curl, curl_infotype type, char *data,
                          size_t size, void *userp)
{
  struct t3236_status *st = (struct t3236_status *)userp;
  static const char want[] = "PAUSE requested";
  static const char buffer_prefix[] = "[PAUSE] buffer ";
  size_t i;
  (void)curl;
  if(type != CURLINFO_TEXT)
    return 0;

  for(i = 0; i + sizeof(buffer_prefix) - 1 <= size; i++) {
    if(!memcmp(&data[i], buffer_prefix, sizeof(buffer_prefix) - 1)) {
      size_t j = i + sizeof(buffer_prefix) - 1;
      size_t amount = 0;
      while(j < size && data[j] >= '0' && data[j] <= '9') {
        amount = amount * 10 + (size_t)(data[j] - '0');
        j++;
      }
      if(amount >= 4096)
        st->raw_buffered = 1;
      break;
    }
  }

  if(st->pauses == 2 && st->raw_buffered && !st->nested &&
     size >= sizeof(want) - 1) {
    for(i = 0; i + sizeof(want) - 1 <= size; i++) {
      if(!memcmp(&data[i], want, sizeof(want) - 1)) {
        st->nested = 1;
        st->nested_result = curl_easy_pause(st->curl, CURLPAUSE_RECV);
        if(!st->nested_result)
          st->nested_result = curl_easy_pause(st->curl, CURLPAUSE_CONT);
        break;
      }
    }
  }
  return 0;
}

static CURLcode test_lib3236(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;
  struct t3236_status st;
  int running = 1;
  int numfds;
  int msg_count;
  CURLMsg *msg;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);
  curl_global_trace("write");

  easy_init(curl);
  st.curl = curl;

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3236_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &st);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, t3236_header_cb);
  easy_setopt(curl, CURLOPT_HEADERDATA, &st);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, t3236_debug_cb);
  easy_setopt(curl, CURLOPT_DEBUGDATA, &st);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  multi_init(multi);
  multi_add_handle(multi, curl);

  while(running) {
    multi_perform(multi, &running);
    abort_on_test_timeout();
    if(st.header_paused && !st.header_unpaused) {
      st.header_unpaused = 1;
      curlx_wait_ms(500);
      result = curl_easy_pause(curl, CURLPAUSE_CONT);
      if(result)
        goto test_cleanup;
    }
    if(st.pauses == 1 && !st.body_unpaused) {
      st.body_unpaused = 1;
      result = curl_easy_pause(curl, CURLPAUSE_CONT);
      if(result)
        goto test_cleanup;
    }
    if(running)
      multi_poll(multi, NULL, 0, 100, &numfds);
    abort_on_test_timeout();
  }

  do {
    msg = curl_multi_info_read(multi, &msg_count);
    if(msg && (msg->msg == CURLMSG_DONE))
      result = msg->data.result;
  } while(msg);

  if(!result && (!st.header_paused || !st.raw_buffered || !st.nested ||
                 st.pauses != 2 || st.nested_result ||
                 st.header_pause_result)) {
    curl_mfprintf(stderr, "gzip nested flush not exercised "
                  "(writes=%d pauses=%d buffered=%d nested=%d)\n",
                  st.writes, st.pauses, st.raw_buffered, st.nested);
    result = TEST_ERR_FAILURE;
  }

test_cleanup:

  curl_multi_remove_handle(multi, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return result;
}
