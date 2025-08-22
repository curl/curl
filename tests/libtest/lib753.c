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
#include "memdebug.h"

struct t753_transfer_status {
  CURL *easy;
  const char *name;
  bool pause;
  bool is_paused;
  bool seen_welcome;
};

static size_t t753_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t753_transfer_status *st = userp;
  size_t len = size * nmemb;
  (void)ptr;
  if(st->pause) {
    curl_mfprintf(stderr, "[%s] write_cb(len=%zu), PAUSE\n", st->name, len);
    st->is_paused = TRUE;
    return CURL_READFUNC_PAUSE;
  }
  curl_mfprintf(stderr, "[%s] write_cb(len=%zu), CONSUME\n", st->name, len);
  st->is_paused = FALSE;
  return len;
}

static size_t t753_hd_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t753_transfer_status *st = userp;
  size_t len = size * nmemb;
  curl_mfprintf(stderr, "[%s] hd_cb '%.*s'\n", st->name, (int)len, ptr);
  if(!strcmp("230 Welcome you silly person\r\n", ptr)) {
    st->seen_welcome = TRUE;
    st->easy = NULL;
  }
  return len;
}

static bool t753_setup(const char *URL, const char *name,
                       CURL **peasy,
                       struct t753_transfer_status *st)
{
  CURL *easy = NULL;
  CURLcode res = CURLE_OK;

  *peasy = NULL;
  memset(st, 0, sizeof(*st));
  st->name = name;
  st->easy = easy;
  st->pause = TRUE;

  easy_init(easy);

  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, t753_write_cb);
  easy_setopt(easy, CURLOPT_WRITEDATA, st);
  easy_setopt(easy, CURLOPT_HEADERFUNCTION, t753_hd_cb);
  easy_setopt(easy, CURLOPT_HEADERDATA, st);

  easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
  easy_setopt(easy, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(easy, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  *peasy = easy;
  return TRUE;

test_cleanup:
  if(easy)
    curl_easy_cleanup(easy);
  return FALSE;
}

static CURLcode test_lib753(const char *URL)
{
  CURL *easy1 = NULL, *easy2 = NULL;
  CURLM *multi = NULL;
  struct t753_transfer_status st1, st2;
  CURLcode res = CURLE_OK;
  CURLMcode mres;
  int still_running;

  start_test_timing();

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl_mfprintf(stderr, "init multi\n");
  multi = curl_multi_init();
  if(!multi) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  if(!t753_setup(URL, "EASY1", &easy1, &st1))
    goto test_cleanup;

  multi_add_handle(multi, easy1);

  multi_perform(multi, &still_running);
  abort_on_test_timeout();
  curl_mfprintf(stderr, "multi_perform() -> %d running\n", still_running);

  while(still_running) {
    int num;

    /* The purpose of this Test:
     * 1. Violently cleanup EASY1 *without* removing it from the multi
     *    handle first. This MUST discard the connection that EASY1 holds,
     *    as EASY1 is not DONE at this point.
     *    With the env var CURL_FTP_PWD_STOP set, the connection will
     *    have no outstanding data at this point. This would allow
     *    reuse if the connection is not terminated by the cleanup.
     * 2. Add EASY2 for the same URL and observe in the expected result
     *    that the connection is NOT reused, e.g. all FTP commands
     *    are sent again on the new connection.
     */
    if(easy1 && st1.seen_welcome) {
      curl_easy_cleanup(easy1);
      easy1 = NULL;
      if(!easy2) {
        if(!t753_setup(URL, "EASY2", &easy2, &st2))
          goto test_cleanup;
        st2.pause = FALSE;
        multi_add_handle(multi, easy2);
      }
    }

    mres = curl_multi_wait(multi, NULL, 0, 1, &num);
    if(mres != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    abort_on_test_timeout();

    multi_perform(multi, &still_running);
    curl_mfprintf(stderr, "multi_perform() -> %d running\n", still_running);

    abort_on_test_timeout();
  }

test_cleanup:

  if(res)
    curl_mfprintf(stderr, "ERROR: %s\n", curl_easy_strerror(res));

  if(easy1)
    curl_easy_cleanup(easy1);
  if(easy2)
    curl_easy_cleanup(easy2);
  curl_multi_cleanup(multi);
  curl_global_cleanup();

  return res;
}
