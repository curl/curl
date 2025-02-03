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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct transfer_status
{
  FETCH *easy;
  int hd_count;
  int bd_count;
  FETCHcode result;
};

#define KN(a) a, #a

static int geterr(const char *name, FETCHcode val, int lineno)
{
  printf("FETCHINFO_%s returned %d, \"%s\" on line %d\n",
         name, val, fetch_easy_strerror(val), lineno);
  return (int)val;
}

static void report_time(const char *key, const char *where, fetch_off_t time,
                        bool ok)
{
  if (ok)
    printf("%s on %s is OK\n", key, where);
  else
    printf("%s on %s is WRONG: %" FETCH_FORMAT_FETCH_OFF_T "\n",
           key, where, time);
}

static void check_time(FETCH *easy, int key, const char *name,
                       const char *where)
{
  fetch_off_t tval;
  FETCHcode res = fetch_easy_getinfo(easy, (FETCHINFO)key, &tval);
  if (res)
  {
    geterr(name, res, __LINE__);
  }
  else
    report_time(name, where, tval, tval > 0);
}

static void check_time0(FETCH *easy, int key, const char *name,
                        const char *where)
{
  fetch_off_t tval;
  FETCHcode res = fetch_easy_getinfo(easy, (FETCHINFO)key, &tval);
  if (res)
  {
    geterr(name, res, __LINE__);
  }
  else
    report_time(name, where, tval, !tval);
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  size_t len = size * nmemb;

  (void)ptr;
  if (!st->hd_count++)
  {
    /* first header, check some FETCHINFO value to be reported. See #13125 */
    check_time(st->easy, KN(FETCHINFO_CONNECT_TIME_T), "1st header");
    check_time(st->easy, KN(FETCHINFO_PRETRANSFER_TIME_T), "1st header");
    check_time(st->easy, KN(FETCHINFO_STARTTRANSFER_TIME_T), "1st header");
    /* continuously updated */
    check_time(st->easy, KN(FETCHINFO_TOTAL_TIME_T), "1st header");
    /* no SSL, must be 0 */
    check_time0(st->easy, KN(FETCHINFO_APPCONNECT_TIME_T), "1st header");
    /* download not really started */
    check_time0(st->easy, KN(FETCHINFO_SPEED_DOWNLOAD_T), "1st header");
  }
  (void)fwrite(ptr, size, nmemb, stdout);
  return len;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;

  (void)ptr;
  (void)st;
  fwrite(ptr, size, nmemb, stdout);
  return size * nmemb;
}

FETCHcode test(char *URL)
{
  FETCH *fetchs = NULL;
  FETCHcode res = FETCHE_OK;
  struct transfer_status st;

  start_test_timing();

  memset(&st, 0, sizeof(st));

  global_init(FETCH_GLOBAL_ALL);

  easy_init(fetchs);
  st.easy = fetchs; /* to allow callbacks access */

  easy_setopt(fetchs, FETCHOPT_URL, URL);
  easy_setopt(fetchs, FETCHOPT_WRITEFUNCTION, write_callback);
  easy_setopt(fetchs, FETCHOPT_WRITEDATA, &st);
  easy_setopt(fetchs, FETCHOPT_HEADERFUNCTION, header_callback);
  easy_setopt(fetchs, FETCHOPT_HEADERDATA, &st);

  easy_setopt(fetchs, FETCHOPT_NOPROGRESS, 0L);

  res = fetch_easy_perform(fetchs);

  check_time(fetchs, KN(FETCHINFO_CONNECT_TIME_T), "done");
  check_time(fetchs, KN(FETCHINFO_PRETRANSFER_TIME_T), "done");
  check_time(fetchs, KN(FETCHINFO_POSTTRANSFER_TIME_T), "done");
  check_time(fetchs, KN(FETCHINFO_STARTTRANSFER_TIME_T), "done");
  /* no SSL, must be 0 */
  check_time0(fetchs, KN(FETCHINFO_APPCONNECT_TIME_T), "done");
  check_time(fetchs, KN(FETCHINFO_SPEED_DOWNLOAD_T), "done");
  check_time(fetchs, KN(FETCHINFO_TOTAL_TIME_T), "done");

test_cleanup:

  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();

  return res; /* return the final return code */
}
