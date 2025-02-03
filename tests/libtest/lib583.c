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
 * are also available at https://fetch.se/docs/copyright.html.
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
/*
 * This test case is based on the sample code provided by Saqib Ali
 * https://fetch.se/mail/lib-2011-03/0066.html
 */

#include "test.h"

#include <sys/stat.h>

#include "memdebug.h"

FETCHcode test(char *URL)
{
  int stillRunning;
  FETCHM *multiHandle = NULL;
  FETCH *fetch = NULL;
  FETCHcode res = FETCHE_OK;
  FETCHMcode mres;

  assert(test_argc >= 4);

  global_init(FETCH_GLOBAL_ALL);

  multi_init(multiHandle);

  easy_init(fetch);

  easy_setopt(fetch, FETCHOPT_USERPWD, libtest_arg2);
  easy_setopt(fetch, FETCHOPT_SSH_PUBLIC_KEYFILE, test_argv[3]);
  easy_setopt(fetch, FETCHOPT_SSH_PRIVATE_KEYFILE, test_argv[4]);

  easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  easy_setopt(fetch, FETCHOPT_URL, URL);
  easy_setopt(fetch, FETCHOPT_INFILESIZE, (long)5);

  multi_add_handle(multiHandle, fetch);

  /* this tests if removing an easy handle immediately after multi
     perform has been called succeeds or not. */

  fprintf(stderr, "fetch_multi_perform()...\n");

  multi_perform(multiHandle, &stillRunning);

  fprintf(stderr, "fetch_multi_perform() succeeded\n");

  fprintf(stderr, "fetch_multi_remove_handle()...\n");
  mres = fetch_multi_remove_handle(multiHandle, fetch);
  if (mres)
  {
    fprintf(stderr, "fetch_multi_remove_handle() failed, "
                    "with code %d\n",
            (int)mres);
    res = TEST_ERR_MULTI;
  }
  else
    fprintf(stderr, "fetch_multi_remove_handle() succeeded\n");

test_cleanup:

  /* undocumented cleanup sequence - type UB */

  fetch_easy_cleanup(fetch);
  fetch_multi_cleanup(multiHandle);
  fetch_global_cleanup();

  return res;
}
