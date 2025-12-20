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

struct t1541_transfer_status {
  CURL *curl;
  int hd_count;
  int bd_count;
};

#define KN(a) a, #a

static void t1541_geterr(const char *name, CURLcode val, int lineno)
{
  curl_mprintf("CURLINFO_%s returned %d, \"%s\" on line %d\n",
               name, val, curl_easy_strerror(val), lineno);
}

static void report_time(const char *key, const char *where, curl_off_t time,
                        bool ok)
{
  if(ok)
    curl_mprintf("%s on %s is OK\n", key, where);
  else
    curl_mprintf("%s on %s is WRONG: %" CURL_FORMAT_CURL_OFF_T "\n",
                 key, where, time);
}

static void check_time(CURL *curl, int key, const char *name,
                       const char *where)
{
  curl_off_t tval;
  CURLcode result = curl_easy_getinfo(curl, (CURLINFO)key, &tval);
  if(result) {
    t1541_geterr(name, result, __LINE__);
  }
  else
    report_time(name, where, tval, tval > 0);
}

static void check_time0(CURL *curl, int key, const char *name,
                        const char *where)
{
  curl_off_t tval;
  CURLcode result = curl_easy_getinfo(curl, (CURLINFO)key, &tval);
  if(result) {
    t1541_geterr(name, result, __LINE__);
  }
  else
    report_time(name, where, tval, !tval);
}

static size_t t1541_header_callback(char *ptr, size_t size, size_t nmemb,
                                    void *userp)
{
  struct t1541_transfer_status *st = (struct t1541_transfer_status *)userp;
  size_t len = size * nmemb;

  (void)ptr;
  if(!st->hd_count++) {
    /* first header, check some CURLINFO value to be reported. See #13125 */
    check_time(st->curl, KN(CURLINFO_CONNECT_TIME_T), "1st header");
    check_time(st->curl, KN(CURLINFO_PRETRANSFER_TIME_T), "1st header");
    check_time(st->curl, KN(CURLINFO_STARTTRANSFER_TIME_T), "1st header");
    /* continuously updated */
    check_time(st->curl, KN(CURLINFO_TOTAL_TIME_T), "1st header");
    /* no SSL, must be 0 */
    check_time0(st->curl, KN(CURLINFO_APPCONNECT_TIME_T), "1st header");
    /* download not really started */
    check_time0(st->curl, KN(CURLINFO_SPEED_DOWNLOAD_T), "1st header");
  }
  (void)fwrite(ptr, size, nmemb, stdout);
  return len;
}

static size_t t1541_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t1541_transfer_status *st = (struct t1541_transfer_status *)userp;

  (void)ptr;
  (void)st;
  fwrite(ptr, size, nmemb, stdout);
  return size * nmemb;
}

static CURLcode test_lib1541(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  struct t1541_transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);
  st.curl = curl; /* to allow callbacks access */

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t1541_write_cb);
  easy_setopt(curl, CURLOPT_WRITEDATA, &st);
  easy_setopt(curl, CURLOPT_HEADERFUNCTION, t1541_header_callback);
  easy_setopt(curl, CURLOPT_HEADERDATA, &st);

  easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

  result = curl_easy_perform(curl);

  check_time(curl, KN(CURLINFO_CONNECT_TIME_T), "done");
  check_time(curl, KN(CURLINFO_PRETRANSFER_TIME_T), "done");
  check_time(curl, KN(CURLINFO_POSTTRANSFER_TIME_T), "done");
  check_time(curl, KN(CURLINFO_STARTTRANSFER_TIME_T), "done");
  /* no SSL, must be 0 */
  check_time0(curl, KN(CURLINFO_APPCONNECT_TIME_T), "done");
  check_time(curl, KN(CURLINFO_SPEED_DOWNLOAD_T), "done");
  check_time(curl, KN(CURLINFO_TOTAL_TIME_T), "done");

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result; /* return the final return code */
}
