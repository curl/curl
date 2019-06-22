/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/curl.h>

UNITTEST_START

int rc;

rc = _curl_is_slist_option(CURLOPT_HTTPHEADER);
fail_unless(rc != 0, "CURLOPT_HTTPHEADER is an slist option");

rc = _curl_is_string_option(CURLOPT_COOKIE);
fail_unless(rc != 0, "CURLOPT_COOKIE is a string option");

rc = _curl_is_long_option(CURLOPT_TIMEOUT);
fail_unless(rc != 0, "CURLOPT_TIMEOUT is a long option");

rc = _curl_is_off_t_option(CURLOPT_MAX_SEND_SPEED_LARGE);
fail_unless(rc != 0, "CURLOPT_MAX_SEND_SPEED_LARGE is an off_t option");

UNITTEST_STOP
