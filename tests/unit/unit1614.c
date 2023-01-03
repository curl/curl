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
#include "curlcheck.h"

#include "noproxy.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

struct check {
  const char *a;
  const char *n;
  unsigned int bits;
  bool match;
};

struct noproxy {
  const char *a;
  const char *n;
  bool match;
  bool space; /* space separated */
};

UNITTEST_START
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_PROXY)
{
  int i;
  int err = 0;
  struct check list4[]= {
    { "192.160.0.1", "192.160.0.1", 33, FALSE},
    { "192.160.0.1", "192.160.0.1", 32, TRUE},
    { "192.160.0.1", "192.160.0.1", 0, TRUE},
    { "192.160.0.1", "192.160.0.1", 24, TRUE},
    { "192.160.0.1", "192.160.0.1", 26, TRUE},
    { "192.160.0.1", "192.160.0.1", 20, TRUE},
    { "192.160.0.1", "192.160.0.1", 18, TRUE},
    { "192.160.0.1", "192.160.0.1", 12, TRUE},
    { "192.160.0.1", "192.160.0.1", 8, TRUE},
    { "192.160.0.1", "10.0.0.1", 8, FALSE},
    { "192.160.0.1", "10.0.0.1", 32, FALSE},
    { "192.160.0.1", "10.0.0.1", 0, FALSE},
    { NULL, NULL, 0, FALSE} /* end marker */
  };
  struct check list6[]= {
    { "::1", "::1", 0, TRUE},
    { "::1", "::1", 128, TRUE},
    { "::1", "0:0::1", 128, TRUE},
    { "::1", "0:0::1", 129, FALSE},
    { "fe80::ab47:4396:55c9:8474", "fe80::ab47:4396:55c9:8474", 64, TRUE},
    { NULL, NULL, 0, FALSE} /* end marker */
  };
  struct noproxy list[]= {
    { "www.example.com", "localhost .example.com .example.de", TRUE, TRUE},
    { "www.example.com", "localhost,.example.com,.example.de", TRUE, FALSE},
    { "www.example.com.", "localhost,.example.com,.example.de", TRUE, FALSE},
    { "example.com", "localhost,.example.com,.example.de", TRUE, FALSE},
    { "example.com.", "localhost,.example.com,.example.de", TRUE, FALSE},
    { "www.example.com", "localhost,.example.com.,.example.de", TRUE, FALSE},
    { "www.example.com", "localhost,www.example.com.,.example.de",
      TRUE, FALSE},
    { "example.com", "localhost,example.com,.example.de", TRUE, FALSE},
    { "example.com.", "localhost,example.com,.example.de", TRUE, FALSE},
    { "nexample.com", "localhost,example.com,.example.de", FALSE, FALSE},
    { "www.example.com", "localhost,example.com,.example.de", TRUE, FALSE},
    { "127.0.0.1", "127.0.0.1,localhost", TRUE, FALSE},
    { "127.0.0.1", "127.0.0.1,localhost,", TRUE, FALSE},
    { "127.0.0.1", "127.0.0.1/8,localhost,", TRUE, FALSE},
    { "127.0.0.1", "127.0.0.1/28,localhost,", TRUE, FALSE},
    { "127.0.0.1", "127.0.0.1/31,localhost,", TRUE, FALSE},
    { "127.0.0.1", "localhost,127.0.0.1", TRUE, FALSE},
    { "127.0.0.1", "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1."
      "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127."
      "0.0.1.127.0.0.1.127.0.0." /* 128 bytes "address" */, FALSE, FALSE},
    { "127.0.0.1", "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1."
      "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127."
      "0.0.1.127.0.0.1.127.0.0" /* 127 bytes "address" */, FALSE, FALSE},
    { "localhost", "localhost,127.0.0.1", TRUE, FALSE},
    { "localhost", "127.0.0.1,localhost", TRUE, FALSE},
    { "foobar", "barfoo", FALSE, FALSE},
    { "foobar", "foobar", TRUE, FALSE},
    { "192.168.0.1", "foobar", FALSE, FALSE},
    { "192.168.0.1", "192.168.0.0/16", TRUE, FALSE},
    { "192.168.0.1", "192.168.0.0/24", TRUE, FALSE},
    { "192.168.0.1", "192.168.0.0/32", FALSE, FALSE},
    { "192.168.0.1", "192.168.0.0", FALSE, FALSE},
    { "192.168.1.1", "192.168.0.0/24", FALSE, FALSE},
    { "192.168.1.1", "foo, bar, 192.168.0.0/24", FALSE, FALSE},
    { "192.168.1.1", "foo, bar, 192.168.0.0/16", TRUE, FALSE},
    { "[::1]", "foo, bar, 192.168.0.0/16", FALSE, FALSE},
    { "[::1]", "foo, bar, ::1/64", TRUE, FALSE},
    { "bar", "foo, bar, ::1/64", TRUE, FALSE},
    { "BAr", "foo, bar, ::1/64", TRUE, FALSE},
    { "BAr", "foo,,,,,              bar, ::1/64", TRUE, FALSE},
    { "www.example.com", "foo, .example.com", TRUE, FALSE},
    { "www.example.com", "www2.example.com, .example.net", FALSE, FALSE},
    { "example.com", ".example.com, .example.net", TRUE, FALSE},
    { "nonexample.com", ".example.com, .example.net", FALSE, FALSE},
    { NULL, NULL, FALSE, FALSE}
  };
  for(i = 0; list4[i].a; i++) {
    bool match = Curl_cidr4_match(list4[i].a, list4[i].n, list4[i].bits);
    if(match != list4[i].match) {
      fprintf(stderr, "%s in %s/%u should %smatch\n",
              list4[i].a, list4[i].n, list4[i].bits,
              list4[i].match ? "": "not ");
      err++;
    }
  }
  for(i = 0; list6[i].a; i++) {
    bool match = Curl_cidr6_match(list6[i].a, list6[i].n, list6[i].bits);
    if(match != list6[i].match) {
      fprintf(stderr, "%s in %s/%u should %smatch\n",
              list6[i].a, list6[i].n, list6[i].bits,
              list6[i].match ? "": "not ");
      err++;
    }
  }
  for(i = 0; list[i].a; i++) {
    bool spacesep = FALSE;
    bool match = Curl_check_noproxy(list[i].a, list[i].n, &spacesep);
    if(match != list[i].match) {
      fprintf(stderr, "%s in %s should %smatch\n",
              list[i].a, list[i].n,
              list[i].match ? "": "not ");
      err++;
    }
    if(spacesep != list[i].space) {
      fprintf(stderr, "%s is claimed to be %sspace separated\n",
              list[i].n, list[i].space?"":"NOT ");
      err++;
    }
  }
  return err;
}
#else
return 0;
#endif
UNITTEST_STOP
