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
#include "timediff.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *ch = NULL;
  global_init(FETCH_GLOBAL_ALL);

  easy_init(ch);

  easy_setopt(ch, FETCHOPT_URL, URL);
  easy_setopt(ch, FETCHOPT_COOKIEFILE, libtest_arg2);
  res = fetch_easy_perform(ch);
  if (res)
    goto test_cleanup;

  fetch_easy_reset(ch);

  easy_setopt(ch, FETCHOPT_URL, URL);
  easy_setopt(ch, FETCHOPT_COOKIEFILE, libtest_arg2);
  easy_setopt(ch, FETCHOPT_COOKIEJAR, libtest_arg3);
  res = fetch_easy_perform(ch);

test_cleanup:
  fetch_easy_cleanup(ch);
  fetch_global_cleanup();

  return res;
}
