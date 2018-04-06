/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "llist.h"

static CURL *easy;

static CURLcode unit_setup(void)
{
  int res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy)
    return CURLE_OUT_OF_MEMORY;
  return res;
}

static void unit_stop(void)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

UNITTEST_START
  int len;
  char *esc;

  esc = curl_easy_escape(easy, "", -1);
  fail_unless(esc == NULL, "negative string length can't work");

  esc = curl_easy_unescape(easy, "%41%41%41%41", -1, &len);
  fail_unless(esc == NULL, "negative string length can't work");

UNITTEST_STOP
