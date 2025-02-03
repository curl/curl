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
#include "testtrace.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

static int xferinfo(void *p,
                    fetch_off_t dltotal, fetch_off_t dlnow,
                    fetch_off_t ultotal, fetch_off_t ulnow)
{
  (void)p;
  (void)dlnow;
  (void)dltotal;
  (void)ulnow;
  (void)ultotal;
  fprintf(stderr, "xferinfo fail!\n");
  return 1; /* fail as fast as we can */
}

FETCHcode test(char *URL)
{
  FETCH *fetchs = NULL;
  FETCHM *multi = NULL;
  int still_running;
  FETCHcode i = FETCHE_OK;
  FETCHcode res = FETCHE_OK;
  fetch_mimepart *field = NULL;
  fetch_mime *mime = NULL;
  int counter = 1;

  start_test_timing();

  global_init(FETCH_GLOBAL_ALL);

  multi_init(multi);

  easy_init(fetchs);

  mime = fetch_mime_init(fetchs);
  field = fetch_mime_addpart(mime);
  fetch_mime_name(field, "name");
  fetch_mime_data(field, "value", FETCH_ZERO_TERMINATED);

  easy_setopt(fetchs, FETCHOPT_URL, URL);
  easy_setopt(fetchs, FETCHOPT_HEADER, 1L);
  easy_setopt(fetchs, FETCHOPT_VERBOSE, 1L);
  easy_setopt(fetchs, FETCHOPT_MIMEPOST, mime);
  easy_setopt(fetchs, FETCHOPT_USERPWD, "u:s");
  easy_setopt(fetchs, FETCHOPT_XFERINFOFUNCTION, xferinfo);
  easy_setopt(fetchs, FETCHOPT_NOPROGRESS, 1L);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  test_setopt(fetchs, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(fetchs, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(fetchs, FETCHOPT_VERBOSE, 1L);

  multi_add_handle(multi, fetchs);

  multi_perform(multi, &still_running);

  abort_on_test_timeout();

  while (still_running && counter--)
  {
    FETCHMcode mres;
    int num;
    mres = fetch_multi_wait(multi, NULL, 0, TEST_HANG_TIMEOUT, &num);
    if (mres != FETCHM_OK)
    {
      printf("fetch_multi_wait() returned %d\n", mres);
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    abort_on_test_timeout();

    multi_perform(multi, &still_running);

    abort_on_test_timeout();
  }

test_cleanup:

  fetch_mime_free(mime);
  fetch_multi_remove_handle(multi, fetchs);
  fetch_multi_cleanup(multi);
  fetch_easy_cleanup(fetchs);
  fetch_global_cleanup();

  if (res)
    i = res;

  return i; /* return the final return code */
}
