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

        const char *rc;

        rc = Curl_prefixed_val("iii", "III", strlen("iii"));
        fail_unless(!strcmp(rc, ""), "return code should be non-zero");

        rc = Curl_prefixed_val("iiia", "III", strlen("iiia"));
        fail_unless(rc == NULL, "return should be null");

        rc = Curl_prefixed_val("iii", "IIIa", strlen("iii"));
        fail_unless(!strcmp(rc, "a"), "return code should be zero");

        rc = Curl_prefixed_val("iiiA", "IIIa", strlen("iiiA"));
        fail_unless(!strcmp(rc, ""), "return code should be non-zero");

        rc = Curl_prefixed_val("iiiABC", "IIIcba", 3);
        fail_unless(!strcmp(rc, "cba"), "return code should be non-zero");

        rc = Curl_prefixed_val("ii", "II", 3);
        fail_unless(rc == NULL,"return code should be null");

UNITTEST_STOP
