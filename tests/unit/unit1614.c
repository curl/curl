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
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "unitcheck.h"
#include "proxy.h"

static CURLcode test_unit1614(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_PROXY)
  int i;
  int err = 0;

  struct check {
    const char *a;
    const char *n;
    int bits;
    bool match;
  };
  struct check list4[] = {
    { "192.160.0.1", "192.160.0.1", 33, FALSE },
    { "192.160.0.1", "192.160.0.1", 32, TRUE },
    { "192.160.0.1", "192.160.0.1", 31, TRUE },
    { "192.160.0.1", "192.160.0.1", 30, TRUE },
    { "192.160.0.1", "192.160.0.1", 29, TRUE },
    { "192.160.0.1", "192.160.0.1", 28, TRUE },
    { "192.160.0.1", "192.160.0.1", 27, TRUE },
    { "192.160.0.1", "192.160.0.1", 26, TRUE },
    { "192.160.0.1", "192.160.0.1", 25, TRUE },
    { "192.160.0.1", "192.160.0.1", 24, TRUE },
    { "192.160.0.1", "192.160.0.1", 23, TRUE },
    { "192.160.0.1", "192.160.0.1", 22, TRUE },
    { "192.160.0.1", "192.160.0.1", 21, TRUE },
    { "192.160.0.1", "192.160.0.1", 20, TRUE },
    { "192.160.0.1", "192.160.0.1", 19, TRUE },
    { "192.160.0.1", "192.160.0.1", 18, TRUE },
    { "192.160.0.1", "192.160.0.1", 17, TRUE },
    { "192.160.0.1", "192.160.0.1", 16, TRUE },
    { "192.160.0.1", "192.160.0.1", 15, TRUE },
    { "192.160.0.1", "192.160.0.1", 14, TRUE },
    { "192.160.0.1", "192.160.0.1", 13, TRUE },
    { "192.160.0.1", "192.160.0.1", 12, TRUE },
    { "192.160.0.1", "192.160.0.1", 11, TRUE },
    { "192.160.0.1", "192.160.0.1", 10, TRUE },
    { "192.160.0.1", "192.160.0.1", 9, TRUE },
    { "192.160.0.1", "192.160.0.1", 8, TRUE },
    { "192.160.0.1", "192.160.0.1", 7, TRUE },
    { "192.160.0.1", "192.160.0.1", 6, TRUE },
    { "192.160.0.1", "192.160.0.1", 5, TRUE },
    { "192.160.0.1", "192.160.0.1", 4, TRUE },
    { "192.160.0.1", "192.160.0.1", 3, TRUE },
    { "192.160.0.1", "192.160.0.1", 2, TRUE },
    { "192.160.0.1", "192.160.0.1", 1, TRUE },
    { "192.160.0.1", "192.160.0.1", 0, TRUE },
    { "192.160.0.1", "192.160.0.1", -1, TRUE },
    { "192.160.0.1", "10.0.0.1", 8, FALSE },
    { "192.160.0.1", "10.0.0.1", 32, FALSE },
    { "192.160.0.1", "10.0.0.1", -1, FALSE },
    { "192.160.0.1", "10.0.0.1", 0, TRUE },
    { "192.160.0.1", "0.0.0.0", 0, TRUE },
    { "0.0.0.1", "0.0.0.0", 0, TRUE },
    { "127.0.0.1", "0.0.0.0", 0, TRUE },
    { "0.0.0.1", "0.0.0.0", -1, FALSE },
    { "127.0.0.1", "0.0.0.0", -1, FALSE },
    { NULL, NULL, 0, FALSE } /* end marker */
  };

#define ADDR1614 "ac1d:f00d:cafe:deb7:ea57:face:f157:51de"
#ifdef USE_IPV6
  struct check list6[] = {
    { "::1", "::1", 0, TRUE },
    { "::1", "::1", 128, TRUE },
    { "::1", "0:0::1", 128, TRUE },
    { "::1", "0:0::1", 129, FALSE },
    { "fe80::ab47:4396:55c9:8474", "fe80::ab47:4396:55c9:8474", 64, TRUE },
    { "fe80::ab47:4396:55c9:8474", "::", 0, TRUE },
    { "::1", "::", 0, TRUE },
    { "::1", "::", -1, FALSE },
    { ADDR1614, ADDR1614, -1, TRUE },
    { ADDR1614, ADDR1614, 0, TRUE },
    { ADDR1614, ADDR1614, 1, TRUE },
    { ADDR1614, ADDR1614, 2, TRUE },
    { ADDR1614, ADDR1614, 3, TRUE },
    { ADDR1614, ADDR1614, 4, TRUE },
    { ADDR1614, ADDR1614, 5, TRUE },
    { ADDR1614, ADDR1614, 6, TRUE },
    { ADDR1614, ADDR1614, 7, TRUE },
    { ADDR1614, ADDR1614, 8, TRUE },
    { ADDR1614, ADDR1614, 9, TRUE },
    { ADDR1614, ADDR1614, 10, TRUE },
    { ADDR1614, ADDR1614, 11, TRUE },
    { ADDR1614, ADDR1614, 12, TRUE },
    { ADDR1614, ADDR1614, 13, TRUE },
    { ADDR1614, ADDR1614, 14, TRUE },
    { ADDR1614, ADDR1614, 15, TRUE },
    { ADDR1614, ADDR1614, 16, TRUE },
    { ADDR1614, ADDR1614, 17, TRUE },
    { ADDR1614, ADDR1614, 18, TRUE },
    { ADDR1614, ADDR1614, 19, TRUE },
    { ADDR1614, ADDR1614, 20, TRUE },
    { ADDR1614, ADDR1614, 21, TRUE },
    { ADDR1614, ADDR1614, 22, TRUE },
    { ADDR1614, ADDR1614, 23, TRUE },
    { ADDR1614, ADDR1614, 24, TRUE },
    { ADDR1614, ADDR1614, 25, TRUE },
    { ADDR1614, ADDR1614, 26, TRUE },
    { ADDR1614, ADDR1614, 27, TRUE },
    { ADDR1614, ADDR1614, 28, TRUE },
    { ADDR1614, ADDR1614, 29, TRUE },
    { ADDR1614, ADDR1614, 30, TRUE },
    { ADDR1614, ADDR1614, 31, TRUE },
    { ADDR1614, ADDR1614, 32, TRUE },
    { ADDR1614, ADDR1614, 33, TRUE },
    { ADDR1614, ADDR1614, 34, TRUE },
    { ADDR1614, ADDR1614, 35, TRUE },
    { ADDR1614, ADDR1614, 36, TRUE },
    { ADDR1614, ADDR1614, 37, TRUE },
    { ADDR1614, ADDR1614, 38, TRUE },
    { ADDR1614, ADDR1614, 39, TRUE },
    { ADDR1614, ADDR1614, 40, TRUE },
    { ADDR1614, ADDR1614, 41, TRUE },
    { ADDR1614, ADDR1614, 42, TRUE },
    { ADDR1614, ADDR1614, 43, TRUE },
    { ADDR1614, ADDR1614, 44, TRUE },
    { ADDR1614, ADDR1614, 45, TRUE },
    { ADDR1614, ADDR1614, 46, TRUE },
    { ADDR1614, ADDR1614, 47, TRUE },
    { ADDR1614, ADDR1614, 48, TRUE },
    { ADDR1614, ADDR1614, 49, TRUE },
    { ADDR1614, ADDR1614, 50, TRUE },
    { ADDR1614, ADDR1614, 51, TRUE },
    { ADDR1614, ADDR1614, 52, TRUE },
    { ADDR1614, ADDR1614, 53, TRUE },
    { ADDR1614, ADDR1614, 54, TRUE },
    { ADDR1614, ADDR1614, 55, TRUE },
    { ADDR1614, ADDR1614, 56, TRUE },
    { ADDR1614, ADDR1614, 57, TRUE },
    { ADDR1614, ADDR1614, 58, TRUE },
    { ADDR1614, ADDR1614, 59, TRUE },
    { ADDR1614, ADDR1614, 60, TRUE },
    { ADDR1614, ADDR1614, 61, TRUE },
    { ADDR1614, ADDR1614, 62, TRUE },
    { ADDR1614, ADDR1614, 63, TRUE },
    { ADDR1614, ADDR1614, 64, TRUE },
    { ADDR1614, ADDR1614, 65, TRUE },
    { ADDR1614, ADDR1614, 66, TRUE },
    { ADDR1614, ADDR1614, 67, TRUE },
    { ADDR1614, ADDR1614, 68, TRUE },
    { ADDR1614, ADDR1614, 69, TRUE },
    { ADDR1614, ADDR1614, 70, TRUE },
    { ADDR1614, ADDR1614, 71, TRUE },
    { ADDR1614, ADDR1614, 72, TRUE },
    { ADDR1614, ADDR1614, 73, TRUE },
    { ADDR1614, ADDR1614, 74, TRUE },
    { ADDR1614, ADDR1614, 75, TRUE },
    { ADDR1614, ADDR1614, 76, TRUE },
    { ADDR1614, ADDR1614, 77, TRUE },
    { ADDR1614, ADDR1614, 78, TRUE },
    { ADDR1614, ADDR1614, 79, TRUE },
    { ADDR1614, ADDR1614, 80, TRUE },
    { ADDR1614, ADDR1614, 81, TRUE },
    { ADDR1614, ADDR1614, 82, TRUE },
    { ADDR1614, ADDR1614, 83, TRUE },
    { ADDR1614, ADDR1614, 84, TRUE },
    { ADDR1614, ADDR1614, 85, TRUE },
    { ADDR1614, ADDR1614, 86, TRUE },
    { ADDR1614, ADDR1614, 87, TRUE },
    { ADDR1614, ADDR1614, 88, TRUE },
    { ADDR1614, ADDR1614, 89, TRUE },
    { ADDR1614, ADDR1614, 90, TRUE },
    { ADDR1614, ADDR1614, 91, TRUE },
    { ADDR1614, ADDR1614, 92, TRUE },
    { ADDR1614, ADDR1614, 93, TRUE },
    { ADDR1614, ADDR1614, 94, TRUE },
    { ADDR1614, ADDR1614, 95, TRUE },
    { ADDR1614, ADDR1614, 96, TRUE },
    { ADDR1614, ADDR1614, 97, TRUE },
    { ADDR1614, ADDR1614, 98, TRUE },
    { ADDR1614, ADDR1614, 99, TRUE },
    { ADDR1614, ADDR1614, 100, TRUE },
    { ADDR1614, ADDR1614, 101, TRUE },
    { ADDR1614, ADDR1614, 102, TRUE },
    { ADDR1614, ADDR1614, 103, TRUE },
    { ADDR1614, ADDR1614, 104, TRUE },
    { ADDR1614, ADDR1614, 105, TRUE },
    { ADDR1614, ADDR1614, 106, TRUE },
    { ADDR1614, ADDR1614, 107, TRUE },
    { ADDR1614, ADDR1614, 108, TRUE },
    { ADDR1614, ADDR1614, 109, TRUE },
    { ADDR1614, ADDR1614, 110, TRUE },
    { ADDR1614, ADDR1614, 111, TRUE },
    { ADDR1614, ADDR1614, 112, TRUE },
    { ADDR1614, ADDR1614, 113, TRUE },
    { ADDR1614, ADDR1614, 114, TRUE },
    { ADDR1614, ADDR1614, 115, TRUE },
    { ADDR1614, ADDR1614, 116, TRUE },
    { ADDR1614, ADDR1614, 117, TRUE },
    { ADDR1614, ADDR1614, 118, TRUE },
    { ADDR1614, ADDR1614, 119, TRUE },
    { ADDR1614, ADDR1614, 120, TRUE },
    { ADDR1614, ADDR1614, 121, TRUE },
    { ADDR1614, ADDR1614, 122, TRUE },
    { ADDR1614, ADDR1614, 123, TRUE },
    { ADDR1614, ADDR1614, 124, TRUE },
    { ADDR1614, ADDR1614, 125, TRUE },
    { ADDR1614, ADDR1614, 126, TRUE },
    { ADDR1614, ADDR1614, 127, TRUE },
    { ADDR1614, ADDR1614, 128, TRUE },
    { ADDR1614, ADDR1614, 129, FALSE },
    { NULL, NULL, 0, FALSE } /* end marker */
  };
#endif
  struct noproxy {
    const char *a;
    const char *n;
    bool match;
  };
  struct noproxy list[] = {
    { "www.example.com", "localhost .example.com .example.de", FALSE },
    { "www.example.com", "localhost,.example.com,.example.de", TRUE },
    { "www.example.com.", "localhost,.example.com,.example.de", TRUE },
    { "example.com", "localhost,.example.com,.example.de", TRUE },
    { "example.com.", "localhost,.example.com,.example.de", TRUE },
    { "www.example.com", "localhost,.example.com.,.example.de", TRUE },
    { "www.example.com", "localhost,www.example.com.,.example.de", TRUE },
    { "example.com", "localhost,example.com,.example.de", TRUE },
    { "example.com.", "localhost,example.com,.example.de", TRUE },
    { "nexample.com", "localhost,example.com,.example.de", FALSE },
    { "www.example.com", "localhost,example.com,.example.de", TRUE },
    { "127.0.0.1", "127.0.0.1,localhost", TRUE },
    { "127.0.0.1", "127.0.0.1,localhost,", TRUE },
    { "127.0.0.1", "127.0.0.1/8,localhost,", TRUE },
    { "127.0.0.1", "127.0.0.1/28,localhost,", TRUE },
    { "127.0.0.1", "127.0.0.1/31,localhost,", TRUE },
    { "127.0.0.1", "localhost,127.0.0.1", TRUE },
    { "127.0.0.1", "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1."
      "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127."
      "0.0.1.127.0.0.1.127.0.0." /* 128 bytes "address" */, FALSE },
    { "127.0.0.1", "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1."
      "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127."
      "0.0.1.127.0.0.1.127.0.0" /* 127 bytes "address" */, FALSE },
    { "localhost", "localhost,127.0.0.1", TRUE },
    { "localhost", "127.0.0.1,localhost", TRUE },
    { "foobar", "barfoo", FALSE },
    { "foobar", "foobar", TRUE },
    { "192.168.0.1", "foobar", FALSE },
    { "192.168.0.1", "192.168.0.0/16", TRUE },
    { "192.168.0.1", "192.168.0.0/16a", FALSE },
    { "192.168.0.1", "192.168.0.0/16 ", TRUE },
    { "192.168.0.1", "192.168.0.0/a16", FALSE },
    { "192.168.0.1", "192.168.0.0/ 16", FALSE },
    { "192.168.0.1", "192.168.0.0/24", TRUE },
    { "192.168.0.1", "192.168.0.0/32", FALSE },
    { "192.168.0.1", "192.168.0.1/32", TRUE },
    { "192.168.0.1", "192.168.0.1/33", FALSE },
    { "192.168.0.1", "192.168.0.0", FALSE },
    { "192.168.1.1", "192.168.0.0/24", FALSE },
    { "192.168.1.1", "192.168.0.0/33", FALSE },
    { "192.168.1.1", "foo, bar, 192.168.0.0/24", FALSE },
    { "192.168.1.1", "foo, bar, 192.168.0.0/16", TRUE },
    { "192.168.1.1", "0.0.0.0/0", TRUE },
    { "192.168.1.1", "0.0.0.0", FALSE },
#ifdef USE_IPV6
    { "::1", "::/0", TRUE },
    { "::1", "::", FALSE },
    { "::1", "::/128", FALSE },
    { "::1", "foo, bar, 192.168.0.0/16", FALSE },
    { "::1", "foo, bar, ::1/64", TRUE },
    { "::1", "::1/64", TRUE },
    { "::1", "::1/96", TRUE },
    { "::1", "::1/129", FALSE },
    { "::1", "::1/128", TRUE },
    { "::1", "::1/127", TRUE },
    { "::1", "::1/a127", FALSE },
    { "::1", "::1/127a", FALSE },
    { "::1", "::1/ 127", FALSE },
    { "::1", "::1/127 ", TRUE },
    { "::1", "::1/126", TRUE },
    { "::1", "::1/125", TRUE },
    { "::1", "::1/124", TRUE },
    { "::1", "::1/123", TRUE },
    { "::1", "::1/122", TRUE },
    { "2001:db8:8000::1", "2001:db8::/65", FALSE },
    { "2001:db8:8000::1", "2001:db8::/66", FALSE },
    { "2001:db8:8000::1", "2001:db8::/67", FALSE },
    { "2001:db8:8000::1", "2001:db8::/68", FALSE },
    { "2001:db8:8000::1", "2001:db8::/69", FALSE },
    { "2001:db8:8000::1", "2001:db8::/70", FALSE },
    { "2001:db8:8000::1", "2001:db8::/71", FALSE },
    { "2001:db8:8000::1", "2001:db8::/72", FALSE },
    { "2001:db8::1", "2001:db8::/65", TRUE },
    { "2001:db8::1", "2001:db8::/66", TRUE },
    { "2001:db8::1", "2001:db8::/67", TRUE },
    { "2001:db8::1", "2001:db8::/68", TRUE },
    { "2001:db8::1", "2001:db8::/69", TRUE },
    { "2001:db8::1", "2001:db8::/70", TRUE },
    { "2001:db8::1", "2001:db8::/71", TRUE },
    { "2001:db8::1", "2001:db8::/72", TRUE },
    { "::1", "::1/129", FALSE },
    { "bar", "foo, bar, ::1/64", TRUE },
    { "BAr", "foo, bar, ::1/64", TRUE },
    { "BAr", "foo,,,,,              bar, ::1/64", TRUE },
#endif
    { "www.example.com", "foo, .example.com", TRUE },
    { "www.example.com", "www2.example.com, .example.net", FALSE },
    { "example.com", ".example.com, .example.net", TRUE },
    { "nonexample.com", ".example.com, .example.net", FALSE },
    { NULL, NULL, FALSE }
  };
  for(i = 0; list4[i].a; i++) {
    bool match = cidr4_match(list4[i].a, list4[i].n, list4[i].bits);
    if(match != list4[i].match) {
      curl_mfprintf(stderr, "%s in %s/%d should %smatch\n",
                    list4[i].a, list4[i].n, list4[i].bits,
                    list4[i].match ? "" : "not ");
      err++;
    }
  }
#ifdef USE_IPV6
  for(i = 0; list6[i].a; i++) {
    bool match = cidr6_match(list6[i].a, list6[i].n, list6[i].bits);
    if(match != list6[i].match) {
      curl_mfprintf(stderr, "%s in %s/%d should %smatch\n",
                    list6[i].a, list6[i].n, list6[i].bits,
                    list6[i].match ? "" : "not ");
      err++;
    }
  }
#endif
  for(i = 0; list[i].a; i++) {
    bool match = proxy_check_noproxy(list[i].a, list[i].n);
    if(match != list[i].match) {
      curl_mfprintf(stderr, "%s in %s should %smatch\n",
                    list[i].a, list[i].n,
                    list[i].match ? "" : "not ");
      err++;
    }
  }
  fail_if(err, "errors");
#endif

  UNITTEST_END_SIMPLE
}
