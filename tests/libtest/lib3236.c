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
  int paused;  /* paused by the body callback and not resumed yet */
  int nested;  /* nested pause + unpause done */
  int raw_buffered; /* at least 4096 compressed bytes waiting for replay */
  int header_paused;
  int header_unpaused;
  CURLcode nested_result;
  CURLcode header_pause_result;
};

static size_t t3236_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userp)
{
  struct t3236_status *st = (struct t3236_status *)userp;
  size_t len = size * nmemb;
  st->writes++;
  /* Pause on every full decoder-sized delivery until the nested unpause has
     run. How much of the body arrives in the same socket read as the final
     header varies, so the number of pauses needed before the replay holds
     enough raw bytes varies too. */
  if(!st->nested && len >= 4000) {
    st->pauses++;
    st->paused = 1;
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
  static const char total_prefix[] = "total=";
  size_t i;
  (void)curl;
  if(type != CURLINFO_TEXT)
    return 0;

  /* "[PAUSE] buffer N more bytes of type T, total=M": M raw bytes are
     queued for replay */
  for(i = 0; i + sizeof(buffer_prefix) - 1 <= size; i++) {
    if(!memcmp(&data[i], buffer_prefix, sizeof(buffer_prefix) - 1)) {
      size_t j;
      for(j = i; j + sizeof(total_prefix) - 1 <= size; j++) {
        if(!memcmp(&data[j], total_prefix, sizeof(total_prefix) - 1)) {
          size_t queued = 0;
          j += sizeof(total_prefix) - 1;
          while(j < size && data[j] >= '0' && data[j] <= '9') {
            queued = queued * 10 + (size_t)(data[j] - '0');
            j++;
          }
          if(queued >= 4096)
            st->raw_buffered = 1;
          break;
        }
      }
      break;
    }
  }

  /* once enough raw bytes are queued, the next pause happens from inside
     their replay: do the nested unpause there */
  if(st->raw_buffered && !st->nested && size >= sizeof(want) - 1) {
    for(i = 0; i + sizeof(want) - 1 <= size; i++) {
      if(!memcmp(&data[i], want, sizeof(want) - 1)) {
        st->nested = 1;
        st->nested_result = curl_easy_pause(st->curl, CURLPAUSE_RECV);
        if(!st->nested_result)
          st->nested_result = curl_easy_pause(st->curl, CURLPAUSE_CONT);
        if(!st->nested_result) {
          /* resumed from in here, the main loop must not do it again */
          st->paused = 0;
        }
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
    if(st.paused) {
      /* resume after each body pause; the replay pauses again until the
         nested unpause has run from inside it */
      st.paused = 0;
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

  if(!result && (!st.header_paused || !st.pauses || !st.raw_buffered ||
                 !st.nested || st.nested_result || st.header_pause_result)) {
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
