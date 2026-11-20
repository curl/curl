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
#include <string.h>

/* Test the recycling of a completed easy handle from inside the
 * CURLMNOTIFY_EASY_DONE callback. The callback resets the handle (clearing
 * USERPWD and the custom header list), frees the header list, removes and
 * re-adds the handle. The second transfer must then go out without the
 * first transfer's Authorization or custom headers.
 *
 * Since 8.22.0 the reset is silently dropped when called from the notify
 * callback (the easy API guard refuses the call while the multi callstack
 * is non-empty), so the second request goes out with the stale headers
 * read from the freed list. See issue #23846.
 */

static CURL *t3108_easy;
static struct curl_slist *t3108_headers;
static int t3108_transfers;
static int t3108_recycled;
static CURLMcode t3108_mres = CURLM_OK;
static CURLcode t3108_ures = CURLE_OK;
static CURLMcode t3108_rres = CURLM_OK;
static CURLcode t3108_ares = CURLE_OK;
static char t3108_hdrlog[32768];
static size_t t3108_hdrlog_len;

static const char *t3108_url;

static size_t t3108_log_append(const char *ptr, size_t len)
{
  if(t3108_hdrlog_len + len >= sizeof(t3108_hdrlog))
    len = sizeof(t3108_hdrlog) - t3108_hdrlog_len - 1;
  memcpy(t3108_hdrlog + t3108_hdrlog_len, ptr, len);
  t3108_hdrlog_len += len;
  t3108_hdrlog[t3108_hdrlog_len] = 0;
  return len;
}

static int t3108_debug_cb(CURL *handle, curl_infotype type, char *data,
                          size_t size, void *userptr)
{
  (void)handle;
  (void)userptr;
  if(type == CURLINFO_HEADER_OUT && data && size)
    t3108_log_append(data, size);
  return 0;
}

static void t3108_notify_cb(CURLM *multi, unsigned int notification,
                            CURL *easy, void *user_data)
{
  (void)user_data;
  if(notification != CURLMNOTIFY_EASY_DONE || easy != t3108_easy)
    return;
  t3108_transfers++;
  if(t3108_transfers > 1)
    return;                       /* second transfer: nothing to recycle */
  /* recycle the finished handle from inside the callback, in the order
   * the CURLMOPT_NOTIFYFUNCTION man page permits: reset the handle, drop
   * the old header list, remove and re-add for the next job */
  curl_easy_reset(easy);
  t3108_recycled++;
  curl_slist_free_all(t3108_headers);
  t3108_headers = NULL;
  t3108_mres = curl_multi_remove_handle(multi, easy);
  curl_easy_setopt(easy, CURLOPT_URL, t3108_url);
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, t3108_debug_cb);
  t3108_ures = curl_easy_setopt(easy, CURLOPT_HTTPHEADER, NULL);
  t3108_rres = curl_multi_add_handle(multi, easy);
}

static int t3108_count_substr(const char *haystack, const char *needle)
{
  int count = 0;
  size_t nlen = strlen(needle);
  const char *p = haystack;
  for(;;) {
    p = strstr(p, needle);
    if(!p)
      break;
    count++;
    p += nlen;
  }
  return count;
}

static CURLcode test_lib3108(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURLM *multi = NULL;
  int running = 1;
  CURLMsg *msg;
  int queued;
  int auth_count;
  int xtest_count;

  t3108_url = URL;
  memset(t3108_hdrlog, 0, sizeof(t3108_hdrlog));

  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);
  multi_setopt(multi, CURLMOPT_NOTIFYFUNCTION, t3108_notify_cb);
  if(curl_multi_notify_enable(multi, CURLMNOTIFY_EASY_DONE) != CURLM_OK) {
    curl_mfprintf(stderr, "curl_multi_notify_enable() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy_init(t3108_easy);
  t3108_headers = curl_slist_append(NULL, "X-Test: yes");
  if(!t3108_headers) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  easy_setopt(t3108_easy, CURLOPT_URL, URL);
  easy_setopt(t3108_easy, CURLOPT_USERPWD, "test:test");
  easy_setopt(t3108_easy, CURLOPT_HTTPHEADER, t3108_headers);
  easy_setopt(t3108_easy, CURLOPT_VERBOSE, 1L);
  easy_setopt(t3108_easy, CURLOPT_DEBUGFUNCTION, t3108_debug_cb);
  multi_add_handle(multi, t3108_easy);

  while(running) {
    CURLMcode mres = curl_multi_perform(multi, &running);
    if(!mres && running)
      mres = curl_multi_poll(multi, NULL, 0, 1000, NULL);
    if(mres) {
      curl_mfprintf(stderr, "curl_multi failed, with code %d (%s)\n",
                    (int)mres, curl_multi_strerror(mres));
      result = TEST_ERR_MULTI;
      goto test_cleanup;
    }
  }

  /* drain any leftover messages */
  do {
    msg = curl_multi_info_read(multi, &queued);
  } while(msg);

  if(t3108_transfers != 2) {
    curl_mfprintf(stderr, "expected 2 transfers, got %d\n", t3108_transfers);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(t3108_recycled != 1) {
    curl_mfprintf(stderr, "the recycle flow did not run exactly once\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(t3108_mres != CURLM_OK || t3108_ures != CURLE_OK ||
     t3108_rres != CURLM_OK || t3108_ares != CURLE_OK) {
    curl_mfprintf(stderr, "recycle calls returned errors (mres %d, ures %d, "
                  "rres %d, ares %d)\n", (int)t3108_mres, (int)t3108_ures,
                  (int)t3108_rres, (int)t3108_ares);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* the first request carries the credentials and the custom header from
   * the initial options; the recycled second request must carry neither */
  auth_count = t3108_count_substr(t3108_hdrlog,
                                  "Authorization: Basic dGVzdDp0ZXN0");
  xtest_count = t3108_count_substr(t3108_hdrlog, "X-Test: yes");
  if(auth_count != 1) {
    curl_mfprintf(stderr, "expected the first request to carry the "
                  "credentials exactly once, found %d\n", auth_count);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(xtest_count != 1) {
    curl_mfprintf(stderr, "expected the custom header exactly once, "
                  "found %d\n", xtest_count);
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

test_cleanup:
  curl_multi_remove_handle(multi, t3108_easy);
  curl_slist_free_all(t3108_headers);
  curl_multi_cleanup(multi);
  curl_easy_cleanup(t3108_easy);
  curl_global_cleanup();

  return result;
}
