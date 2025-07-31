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

static int t1553_xferinfo(void *p,
                          curl_off_t dltotal, curl_off_t dlnow,
                          curl_off_t ultotal, curl_off_t ulnow)
{
  (void)p;
  (void)dlnow;
  (void)dltotal;
  (void)ulnow;
  (void)ultotal;
  curl_mfprintf(stderr, "xferinfo fail!\n");
  return 1; /* fail as fast as we can */
}

static CURLcode test_lib1553(const char *URL)
{
  CURL *curls = NULL;
  CURLM *multi = NULL;
  int still_running;
  CURLcode i = CURLE_OK;
  CURLcode res = CURLE_OK;
  curl_mimepart *field = NULL;
  curl_mime *mime = NULL;
  int counter = 1;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);

  multi_init(multi);

  easy_init(curls);

  mime = curl_mime_init(curls);
  field = curl_mime_addpart(mime);
  curl_mime_name(field, "name");
  curl_mime_data(field, "value", CURL_ZERO_TERMINATED);

  easy_setopt(curls, CURLOPT_URL, URL);
  easy_setopt(curls, CURLOPT_HEADER, 1L);
  easy_setopt(curls, CURLOPT_VERBOSE, 1L);
  easy_setopt(curls, CURLOPT_MIMEPOST, mime);
  easy_setopt(curls, CURLOPT_USERPWD, "u:s");
  easy_setopt(curls, CURLOPT_XFERINFOFUNCTION, t1553_xferinfo);
  easy_setopt(curls, CURLOPT_NOPROGRESS, 1L);

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  test_setopt(curls, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(curls, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(curls, CURLOPT_VERBOSE, 1L);

  multi_add_handle(multi, curls);

  multi_perform(multi, &still_running);

  abort_on_test_timeout();

  while(still_running && counter--) {
    CURLMcode mres;
    int num;
    mres = curl_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);
    if(mres != CURLM_OK) {
      curl_mprintf("curl_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    abort_on_test_timeout();

    multi_perform(multi, &still_running);

    abort_on_test_timeout();
  }

test_cleanup:

  curl_mime_free(mime);
  curl_multi_remove_handle(multi, curls);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(curls);
  curl_global_cleanup();

  if(res)
    i = res;

  return i; /* return the final return code */
}
