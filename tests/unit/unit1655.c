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

/* introduce a scope and prove the corner case with write overflow,
 * so we can prove this test would detect it and that it is properly fixed
 */
do {
  const char *bad = "this.is.a.hostname.where.each.individual.part.is.within."
    "the.sixtythree.character.limit.but.still.long.enough.to."
    "trigger.the.the.buffer.overflow......it.is.chosen.to.be."
    "of.a.length.such.that.it.causes.a.two.byte.buffer......."
    "overwrite.....making.it.longer.causes.doh.encode.to....."
    ".return.early.so.dont.change.its.length.xxxx.xxxxxxxxxxx"
    "..xxxxxx.....xx..........xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxx..x......xxxx"
    "xxxx..xxxxxxxxxxxxxxxxxxx.x...xxxx.x.x.x...xxxxx";

  /* plays the role of struct dnsprobe in urldata.h */
  struct demo {
    unsigned char dohbuffer[512];
    unsigned char canary1;
    unsigned char canary2;
    unsigned char canary3;
  };

  size_t olen = 100000;
  struct demo victim;
  DOHcode d;
  victim.canary1 = 87; /* magic numbers, arbritrarily picked */
  victim.canary2 = 35;
  victim.canary3 = 41;
  d = doh_encode(bad, DNS_TYPE_A, victim.dohbuffer,
                 sizeof(victim.dohbuffer), &olen);
  fail_unless(victim.canary1 == 87, "one byte buffer overwrite has happened");
  fail_unless(victim.canary2 == 35, "two byte buffer overwrite has happened");
  fail_unless(victim.canary3 == 41,
              "three byte buffer overwrite has happened");
  if(d == DOH_OK) {
    fail_unless(olen <= sizeof(victim.dohbuffer), "wrote outside bounds");
    fail_unless(olen > strlen(bad), "unrealistic low size");
  }
} while(0);

/* run normal cases and try to trigger buffer length related errors */
do {
  DNStype dnstype = DNS_TYPE_A;
  unsigned char buffer[128];
  const size_t buflen = sizeof(buffer);
  const size_t magic1 = 9765;
  size_t olen1 = magic1;
  const char *sunshine1 = "a.com";
  const char *sunshine2 = "aa.com";
  size_t olen2;
  DOHcode ret2;
  size_t olen;

  DOHcode ret = doh_encode(sunshine1, dnstype, buffer, buflen, &olen1);
  fail_unless(ret == DOH_OK, "sunshine case 1 should pass fine");
  fail_if(olen1 == magic1, "olen has not been assigned properly");
  fail_unless(olen1 > strlen(sunshine1), "bad out length");

  /* add one letter, the response should be one longer */
  olen2 = magic1;
  ret2 = doh_encode(sunshine2, dnstype, buffer, buflen, &olen2);
  fail_unless(ret2 == DOH_OK, "sunshine case 2 should pass fine");
  fail_if(olen2 == magic1, "olen has not been assigned properly");
  fail_unless(olen1 + 1 == olen2, "olen should grow with the hostname");

  /* pass a short buffer, should fail */
  ret = doh_encode(sunshine1, dnstype, buffer, olen1 - 1, &olen);
  fail_if(ret == DOH_OK, "short buffer should have been noticed");

  /* pass a minimum buffer, should succeed */
  ret = doh_encode(sunshine1, dnstype, buffer, olen1, &olen);
  fail_unless(ret == DOH_OK, "minimal length buffer should be long enough");
  fail_unless(olen == olen1, "bad buffer length");
} while(0);
UNITTEST_STOP
