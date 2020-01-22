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

#ifndef CURL_DISABLE_DOH

UNITTEST_START

/*
 * Prove detection of write overflow using a short buffer and a name
 * of maximal valid length.
 *
 * Prove detection of other invalid input.
 */
do {
  const char *submax =
    /* ..|....1.........2.........3.........4.........5.........6... */
    /* 3456789012345678901234567890123456789012345678901234567890123 */
    "this.is.a.long.hostname."                            /* 24:  24 */
    "with-no-label-of-greater-length-than-the-sixty-three-characters."
                                                          /* 64:  88 */
    "specified.in.the.RFCs."                              /* 22: 110 */
    "and.with.a.QNAME.encoding.whose.length.is."          /* 42: 152 */
    "a.little.shorter.than.the.maximum."                  /* 34: 186 */
    "that.is.two-hundred.and.fifty-six."                  /* 34: 220 */
    "including.the.last.null."                            /* 24: 244 */
    "";                                                 /* slack: 11 */
  const char *max =
    /* ..|....1.........2.........3.........4.........5.........6... */
    /* 3456789012345678901234567890123456789012345678901234567890123 */
    "this.is.a.maximum-length.hostname."                  /* 34:  34 */
    "with-no-label-of-greater-length-than-the-sixty-three-characters."
                                                          /* 64:  98 */
    "specified.in.the.RFCs."                              /* 22: 120 */
    "and.with.a.QNAME.encoding.whose.length.is.exactly."  /* 50: 170 */
    "the.maximum.length.allowed."                         /* 27: 197 */
    "that.is.two-hundred.and.fifty-six."                  /* 34: 231 */
    "including.the.last.null."                            /* 24: 255 */
    "";
  const char *toolong =
    /* ..|....1.........2.........3.........4.........5.........6... */
    /* 3456789012345678901234567890123456789012345678901234567890123 */
    "here.is.a.hostname.which.is.just.barely.too.long."   /* 49:  49 */
    "to.be.encoded.as.a.QNAME.of.the.maximum.allowed.length."
                                                          /* 55: 104 */
    "which.is.256.including.a.final.zero-length.label."   /* 49: 153 */
    "representing.the.root.node.so.that.a.name.with."     /* 47: 200 */
    "a.trailing.dot.may.have.up.to."                      /* 30: 230 */
    "255.characters.never.more."                          /* 26: 256 */
    "";
  const char *emptylabel =
    "this.is.an.otherwise-valid.hostname."
    ".with.an.empty.label.";
  const char *outsizelabel =
    "this.is.an.otherwise-valid.hostname."
    "with-a-label-of-greater-length-than-the-sixty-three-characters-"
    "specified.in.the.RFCs.";

  struct test {
    const char *name;
    const char *prefix;
    const DOHcode expected_result;
    const int overflow;
  };

  /* plays the role of struct dnsprobe in urldata.h */
  struct demo {
    unsigned char dohbuffer[256 + 16]; /* full-size buffer */
    unsigned char canary1;
    unsigned char canary2;
    unsigned char canary3;
  };

  const char *message[] = {
    "DOH_OK",
    "DOH_DNS_BAD_LABEL",
    "DOH_DNS_OUT_OF_RANGE",
    "DOH_DNS_LABEL_LOOP",
    "DOH_TOO_SMALL_BUFFER",
    "DOH_OUT_OF_MEM",
    "DOH_DNS_RDATA_LEN",
    "DOH_DNS_MALFORMAT",
    "DOH_DNS_BAD_RCODE",
    "DOH_DNS_UNEXPECTED_TYPE",
    "DOH_DNS_UNEXPECTED_CLASS",
    "DOH_NO_CONTENT",
    "DOH_DNS_BAD_ID",
    "DOH_DNS_NAME_TOO_LONG"
  };

  const struct test playlist[] = {
    /* tests without prefix */
    { toolong, NULL, DOH_DNS_NAME_TOO_LONG, 0 },  /* expect early failure */
    { ".", NULL, DOH_DNS_BAD_LABEL, 0 },          /* also */
    { emptylabel, NULL, DOH_DNS_BAD_LABEL, 0 },   /* also */
    { outsizelabel, NULL, DOH_DNS_BAD_LABEL, 0 }, /* also */
    { max, NULL, DOH_OK, 2 },                     /* trigger 2x overwrite */
    /* tests with (perhaps empty) prefix */
    { submax, "", DOH_OK, 0 },                    /* empty prefix */
    { submax, ".", DOH_DNS_BAD_LABEL, 0 },        /* prefix begins with dot */
    { submax, "_short.", DOH_OK, 0 },             /* well within slack */
    { submax, "_very._max.", DOH_OK, 1 },         /* just within slack */
    { submax, "_more._than.", DOH_DNS_NAME_TOO_LONG, 0 } /* just too long */
  };

  for(int i = 0; i < (int)(sizeof(playlist)/sizeof(*playlist)); i++) {
    const char *name = playlist[i].name;
    const char *prefix = playlist[i].prefix;
    size_t olen = 100000;
    struct demo victim;
    int offset = playlist[i].overflow;
    DOHcode d;

    fail_if(offset > 2, "misconfigured unit-test: offset too great");

    victim.canary1 = 87; /* magic numbers, arbritrarily picked */
    victim.canary2 = 35;
    victim.canary3 = 41;
    d = doh_encode(name, prefix, DNS_TYPE_A,
                   victim.dohbuffer + offset, /* buffer shortened */
                   sizeof(victim.dohbuffer),  /* allow for overflow */
                   &olen);

    fail_unless(d == playlist[i].expected_result,
                "result returned was not as expected");
    if(d == playlist[i].expected_result) {
      if(offset > 0) {
        fail_if(victim.canary1 == 87,
                "demo one-byte buffer overwrite did not happen");
      }
      else {
        fail_unless(victim.canary1 == 87,
                    "one-byte buffer overwrite has happened");
      }
      if(offset > 1) {
        fail_if(victim.canary2 == 35,
                  "demo two-byte buffer overwrite did not happen");
      }
      else {
        fail_unless(victim.canary2 == 35,
                  "two-byte buffer overwrite has happened");
      }

      /* not triggered in playlist, so must be an error */
      fail_unless(victim.canary3 == 41,
                  "three-byte buffer overwrite has happened");
    }
    else {

      /* give some clue as to what happened */
      fprintf(stderr, "\n  result: %d (%s); expected: %d (%s)\n",
              d, message[d],
              playlist[i].expected_result,
              message[playlist[i].expected_result]);
      fprintf(stderr, "  name: (%ld) '%s'\n", strlen(name), name);
      if(prefix)
        fprintf(stderr, "  prefix: (%ld) '%s'\n", strlen(prefix), prefix);
      else
        fprintf(stderr, "  no prefix\n");

      if(d == DOH_OK) {
        fail_unless(olen <= sizeof(victim.dohbuffer), "wrote outside bounds");
        fail_unless(olen > strlen(name), "unrealistic low size");
      }
    }
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
  const char *dotshine1 = "a.com.";
  const char *sunshine2 = "aa.com";
  size_t olen2;
  DOHcode ret2;
  size_t olen;

  DOHcode ret = doh_encode(sunshine1, NULL, dnstype, buffer, buflen, &olen1);
  fail_unless(ret == DOH_OK, "sunshine case 1 should pass fine");
  fail_if(olen1 == magic1, "olen has not been assigned properly");
  fail_unless(olen1 > strlen(sunshine1), "bad out length");

  /* with a trailing dot, the response should have the same length */
  olen2 = magic1;
  ret2 = doh_encode(dotshine1, NULL, dnstype, buffer, buflen, &olen2);
  fail_unless(ret2 == DOH_OK, "dotshine case should pass fine");
  fail_if(olen2 == magic1, "olen has not been assigned properly");
  fail_unless(olen1 == olen2, "olen should not grow for a trailing dot");

  /* add one letter, the response should be one longer */
  olen2 = magic1;
  ret2 = doh_encode(sunshine2, NULL, dnstype, buffer, buflen, &olen2);
  fail_unless(ret2 == DOH_OK, "sunshine case 2 should pass fine");
  fail_if(olen2 == magic1, "olen has not been assigned properly");
  fail_unless(olen1 + 1 == olen2, "olen should grow with the hostname");

  /* pass a short buffer, should fail */
  ret = doh_encode(sunshine1, NULL, dnstype, buffer, olen1 - 1, &olen);
  fail_if(ret == DOH_OK, "short buffer should have been noticed");

  /* pass a minimum buffer, should succeed */
  ret = doh_encode(sunshine1, NULL, dnstype, buffer, olen1, &olen);
  fail_unless(ret == DOH_OK, "minimal length buffer should be long enough");
  fail_unless(olen == olen1, "bad buffer length");
} while(0);

/* Prove that prefix and name haven't inadvertently been swapped */
do {
  DNStype dnstype = DNS_TYPE_A;
  unsigned char buffer[256 + 16];
  const size_t buflen = sizeof(buffer);
  const char *basename = "example.com";
  const char *prefix = "_dummy";
  unsigned char *p = (unsigned char *)prefix;
  unsigned char *q = buffer + 13; /* move past header and count */
  size_t olen;
  bool order_ok = TRUE;

  DOHcode ret = doh_encode(basename, prefix, dnstype,
                           buffer, buflen, &olen);
  fail_unless(ret == DOH_OK,
              "unexpected failure for ('_dummy', 'example.com'");

  /* First label must match (first label of) prefix */
  while((*p) && (*p != '.')) {
    if(*p++ != *q++) {
      order_ok = FALSE;
      break;
    }
  }
  fail_unless(order_ok == TRUE,
              "first label of result does not match that of prefix");
 } while(0);

UNITTEST_STOP

#else /* CURL_DISABLE_DOH */

UNITTEST_START
{
  return 1; /* nothing to do, just fail */
}
UNITTEST_STOP

#endif
