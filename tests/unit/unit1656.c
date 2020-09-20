/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "strcase.h"
#include "string.h"

static CURLcode unit_setup(void) {return CURLE_OK;}
static void unit_stop(void) {}

UNITTEST_START

const char *returned;

returned = Curl_prefixed_val("abc", "ABC", strlen("abc"));
fail_unless(returned == NULL, "return val should be null");

returned = Curl_prefixed_val("abcd", "ABC", strlen("abcd"));
fail_unless(returned == NULL, "return val should be null");

returned = Curl_prefixed_val("abc", "ABCd", strlen("abc"));
fail_unless(!strcmp(returned, "d"), "returned val should be after prefix");

returned = Curl_prefixed_val("abcD", "ABCd", strlen("abcD"));
fail_unless(returned == NULL, "return val should be null");

returned = Curl_prefixed_val("abcDEF", "ABCfed", 3);
fail_unless(!strcmp(returned, "fed"), "return val should be be after prefix");

returned = Curl_prefixed_val("ab", "AB", 3);
fail_unless(returned == NULL, "return val should be null");

UNITTEST_STOP
