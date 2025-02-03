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
#include "fetchcheck.h"

#include "llist.h"

static FETCH *easy;

static FETCHcode unit_setup(void)
{
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);
  easy = fetch_easy_init();
  if(!easy) {
    fetch_global_cleanup();
    return FETCHE_OUT_OF_MEMORY;
  }
  return res;
}

static void unit_stop(void)
{
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
}

UNITTEST_START
  int len;
  char *esc;

  esc = fetch_easy_escape(easy, "", -1);
  fail_unless(esc == NULL, "negative string length can't work");

  esc = fetch_easy_unescape(easy, "%41%41%41%41", -1, &len);
  fail_unless(esc == NULL, "negative string length can't work");

UNITTEST_STOP
