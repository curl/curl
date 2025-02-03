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
#include "test.h"

#include "testutil.h"
#include "timediff.h"
#include "warnless.h"
#include "memdebug.h"

FETCHcode test(char *URL)
{
  FETCHSH *sh = NULL;
  FETCH *ch = NULL;
  int unfinished;
  FETCHM *cm;

  fetch_global_init(FETCH_GLOBAL_ALL);

  cm = fetch_multi_init();
  if (!cm)
  {
    fetch_global_cleanup();
    return (FETCHcode)1;
  }
  sh = fetch_share_init();
  if (!sh)
    goto cleanup;

  fetch_share_setopt(sh, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);
  fetch_share_setopt(sh, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);

  ch = fetch_easy_init();
  if (!ch)
    goto cleanup;

  fetch_easy_setopt(ch, FETCHOPT_SHARE, sh);
  fetch_easy_setopt(ch, FETCHOPT_URL, URL);
  fetch_easy_setopt(ch, FETCHOPT_COOKIEFILE, libtest_arg2);
  fetch_easy_setopt(ch, FETCHOPT_COOKIEJAR, libtest_arg2);

  fetch_multi_add_handle(cm, ch);

  unfinished = 1;
  while (unfinished)
  {
    int MAX = 0;
    long max_tout;
    fd_set R, W, E;
    struct timeval timeout;

    FD_ZERO(&R);
    FD_ZERO(&W);
    FD_ZERO(&E);
    fetch_multi_perform(cm, &unfinished);

    fetch_multi_fdset(cm, &R, &W, &E, &MAX);
    fetch_multi_timeout(cm, &max_tout);

    if (max_tout > 0)
    {
      fetchx_mstotv(&timeout, max_tout);
    }
    else
    {
      timeout.tv_sec = 0;
      timeout.tv_usec = 1000;
    }

    select(MAX + 1, &R, &W, &E, &timeout);
  }

  fetch_easy_setopt(ch, FETCHOPT_COOKIELIST, "FLUSH");
  fetch_easy_setopt(ch, FETCHOPT_SHARE, NULL);

  fetch_multi_remove_handle(cm, ch);
cleanup:
  fetch_easy_cleanup(ch);
  fetch_share_cleanup(sh);
  fetch_multi_cleanup(cm);
  fetch_global_cleanup();

  return FETCHE_OK;
}
