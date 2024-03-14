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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct transfer_status {
  CURL *easy;
  int hd_count;
  int bd_count;
  CURLcode result;
};

#define KN(a)   a, #a

static int geterr(const char *name, CURLcode val, int lineno)
{
  printf("CURLINFO_%s returned %d, \"%s\" on line %d\n",
         name, val, curl_easy_strerror(val), lineno);
  return (int)val;
}

static void report_time(const char *key, const char *where, curl_off_t time,
                        bool ok)
{
  if(ok)
    printf("%s on %s is OK\n", key, where);
  else
    printf("%s on %s is WRONG: %" CURL_FORMAT_CURL_OFF_T "\n",
           key, where, time);
}

static void check_time(CURL *easy, int key, const char *name,
                       const char *where)
{
  curl_off_t tval;
  CURLcode res = curl_easy_getinfo(easy, (CURLINFO)key, &tval);
  if(res) {
    geterr(name, res, __LINE__);
  }
  else
    report_time(name, where, tval, tval > 0);
}

static void check_time0(CURL *easy, int key, const char *name,
                        const char *where)
{
  curl_off_t tval;
  CURLcode res = curl_easy_getinfo(easy, (CURLINFO)key, &tval);
  if(res) {
    geterr(name, res, __LINE__);
  }
  else
    report_time(name, where, tval, !tval);
}

static size_t header_callback(void *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  size_t len = size * nmemb;

  (void)ptr;
  if(!st->hd_count++) {
    /* first header, check some CURLINFO value to be reported. See #13125 */
    check_time(st->easy, KN(CURLINFO_CONNECT_TIME_T), "1st header");
    check_time(st->easy, KN(CURLINFO_PRETRANSFER_TIME_T), "1st header");
    check_time(st->easy, KN(CURLINFO_STARTTRANSFER_TIME_T), "1st header");
    /* continuously updated */
    check_time(st->easy, KN(CURLINFO_TOTAL_TIME_T), "1st header");
    /* no SSL, must be 0 */
    check_time0(st->easy, KN(CURLINFO_APPCONNECT_TIME_T), "1st header");
    /* download not really started */
    check_time0(st->easy, KN(CURLINFO_SPEED_DOWNLOAD_T), "1st header");
  }
  (void)fwrite(ptr, size, nmemb, stdout);
  return len;
}

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;

  (void)ptr;
  (void)st;
  fwrite(ptr, size, nmemb, stdout);
  return size * nmemb;
}

int test(char *URL)
{
  CURL *curls = NULL;
  int res = 0;
  struct transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curls);
  st.easy = curls; /* to allow callbacks access */

  easy_setopt(curls, CURLOPT_URL, URL);
  easy_setopt(curls, CURLOPT_WRITEFUNCTION, write_callback);
  easy_setopt(curls, CURLOPT_WRITEDATA, &st);
  easy_setopt(curls, CURLOPT_HEADERFUNCTION, header_callback);
  easy_setopt(curls, CURLOPT_HEADERDATA, &st);

  easy_setopt(curls, CURLOPT_NOPROGRESS, 0L);

  res = curl_easy_perform(curls);

  check_time(curls, KN(CURLINFO_CONNECT_TIME_T), "done");
  check_time(curls, KN(CURLINFO_PRETRANSFER_TIME_T), "done");
  check_time(curls, KN(CURLINFO_STARTTRANSFER_TIME_T), "done");
  /* no SSL, must be 0 */
  check_time0(curls, KN(CURLINFO_APPCONNECT_TIME_T), "done");
  check_time(curls, KN(CURLINFO_SPEED_DOWNLOAD_T), "done");
  check_time(curls, KN(CURLINFO_TOTAL_TIME_T), "done");

test_cleanup:

  curl_easy_cleanup(curls);
  curl_global_cleanup();

  return (int)res; /* return the final return code */
}
