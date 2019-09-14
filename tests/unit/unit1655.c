/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "doh.h" /* from the lib dir */

static CURLcode unit_setup(void)
{
  /* whatever you want done first */
  return CURLE_OK;
}

static void unit_stop(void)
{
    /* done before shutting down and exiting */
}

UNITTEST_START

DNStype dnstype = DNS_TYPE_A;
unsigned char buffer[128];
const size_t buflen = sizeof(buffer);
const size_t magic1 = 9765;
size_t olen1 = magic1;
const char *sunshine1 = "a.com";
const char *sunshine2 = "aa.com";
DOHcode ret = doh_encode(sunshine1, dnstype, buffer, buflen, &olen1);
fail_unless(ret == DOH_OK, "sunshine case 1 should pass fine");
fail_if(olen1 == magic1, "olen has not been assigned properly");
fail_unless(olen1 > strlen(sunshine1), "bad out length");

/* add one letter, the response should be one longer */
size_t olen2 = magic1;
DOHcode ret2 = doh_encode(sunshine2, dnstype, buffer, buflen, &olen2);
fail_unless(ret2 == DOH_OK, "sunshine case 2 should pass fine");
fail_if(olen2 == magic1, "olen has not been assigned properly");
fail_unless(olen1 + 1 == olen2, "olen should grow with the hostname");

/* pass a short buffer, should fail */
size_t olen;
ret = doh_encode(sunshine1, dnstype, buffer, olen1 - 1, &olen);
fail_if(ret == DOH_OK, "short buffer should have been noticed");

/* pass a minimum buffer, should succeed */
ret = doh_encode(sunshine1, dnstype, buffer, olen1, &olen);
fail_unless(ret == DOH_OK, "minimal length buffer should be long enough");
fail_unless(olen == olen1, "bad buffer length");

UNITTEST_STOP
