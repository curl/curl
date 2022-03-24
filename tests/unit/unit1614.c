/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "curlcheck.h"
#include "curl_setup.h"
#include "dynbuf.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

/* it means 10 is too much, it can only fit 9 bytes */
#define MAX_LENGTH 10

UNITTEST_START
{
  char *ptr;
  struct dynbuf buf;
  CURLcode result;
  Curl_dyn_init(&buf, MAX_LENGTH);

  ptr = Curl_dyn_ptr(&buf);
  fail_unless(!ptr, "Curl_dyn_ptr return non-NULL");

  result = Curl_dyn_add(&buf, "one  ");
  fail_unless(result == CURLE_OK, "Curl_dyn_add return code");

  result = Curl_dyn_add(&buf, "two ");
  fail_unless(result == CURLE_OK, "Curl_dyn_add return code");

  ptr = Curl_dyn_ptr(&buf);
  fail_unless(ptr, "Curl_dyn_ptr returned NULL");
  Curl_dyn_reset(&buf);

  ptr = Curl_dyn_ptr(&buf);
  fail_unless(!ptr, "Curl_dyn_ptr return non-NULL");

  result = Curl_dyn_add(&buf, "one two 33"); /* too long */
  fail_unless(result != CURLE_OK, "Curl_dyn_add return code");

  ptr = Curl_dyn_ptr(&buf);
  fail_unless(!ptr, "Curl_dyn_ptr return non-NULL");

  result = Curl_dyn_add(&buf, "one two");
  fail_unless(result == CURLE_OK, "Curl_dyn_add return code");

  Curl_dyn_free(&buf);
}
UNITTEST_STOP
