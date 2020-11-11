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

static CURLcode unit_setup(void) {return CURLE_OK;}
static void unit_stop(void) {}

UNITTEST_START

int rc;

rc = curl_strequal("iii", "III");
fail_unless(rc != 0, "return code should be non-zero");

rc = curl_strequal("iiia", "III");
fail_unless(rc == 0, "return code should be zero");

rc = curl_strequal("iii", "IIIa");
fail_unless(rc == 0, "return code should be zero");

rc = curl_strequal("iiiA", "IIIa");
fail_unless(rc != 0, "return code should be non-zero");

rc = curl_strnequal("iii", "III", 3);
fail_unless(rc != 0, "return code should be non-zero");

rc = curl_strnequal("iiiABC", "IIIcba", 3);
fail_unless(rc != 0, "return code should be non-zero");

rc = curl_strnequal("ii", "II", 3);
fail_unless(rc != 0, "return code should be non-zero");

UNITTEST_STOP
