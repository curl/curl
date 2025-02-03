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

#include "testtrace.h"
#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct transfer_status
{
  FETCH *easy;
  int halted;
  int counter; /* count write callback invokes */
  int please;  /* number of times xferinfo is called while halted */
};

static int please_continue(void *userp,
                           fetch_off_t dltotal,
                           fetch_off_t dlnow,
                           fetch_off_t ultotal,
                           fetch_off_t ulnow)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  if (st->halted)
  {
    st->please++;
    if (st->please == 2)
    {
      /* waited enough, unpause! */
      fetch_easy_pause(st->easy, FETCHPAUSE_CONT);
    }
  }
  fprintf(stderr, "xferinfo: paused %d\n", st->halted);
  return 0; /* go on */
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb,
                              void *userp)
{
  size_t len = size * nmemb;
  (void)userp;
  (void)fwrite(ptr, size, nmemb, stdout);
  return len;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct transfer_status *st = (struct transfer_status *)userp;
  size_t len = size * nmemb;
  st->counter++;
  if (st->counter > 1)
  {
    /* the first call puts us on pause, so subsequent calls are after
       unpause */
    fwrite(ptr, size, nmemb, stdout);
    return len;
  }
  if (len)
    printf("Got bytes but pausing!\n");
  st->halted = 1;
  return FETCH_WRITEFUNC_PAUSE;
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

  easy_setopt(fetchs, FETCHOPT_XFERINFOFUNCTION, please_continue);
  easy_setopt(fetchs, FETCHOPT_XFERINFODATA, &st);
  easy_setopt(fetchs, FETCHOPT_NOPROGRESS, 0L);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  test_setopt(fetchs, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(fetchs, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(fetchs, FETCHOPT_VERBOSE, 1L);

  res = fetch_easy_perform(fetchs);

test_cleanup:

  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();

  return res; /* return the final return code */
}
