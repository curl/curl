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
#include "urldata.h"
#include "altsvc.h"

static CURLcode test_unit1654(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_ALTSVC)
  char outname[256];
  CURL *curl = NULL;
  CURLcode result;
  struct altsvcinfo *asi = Curl_altsvc_init();
  struct altsvc *dstentry = NULL;
  struct Curl_peer *origin = NULL;
  const struct Curl_scheme *scheme = &Curl_scheme_https;
  bool same_destination = FALSE;

  abort_if(!asi, "Curl_altsvc_i");
  result = Curl_altsvc_load(asi, arg);
  fail_if(result, "Curl_altsvc_load");
  if(result)
    goto fail;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  fail_if(!curl, "curl_easy_init");
  if(!curl)
    goto fail;

  fail_unless(Curl_llist_count(&asi->list) == 4, "wrong number of entries");
  curl_msnprintf(outname, sizeof(outname), "%s-out", arg);

  if(Curl_peer_create(curl, scheme, "example.org", 8080, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi, "h2=\"example.com:8080\"\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse() failed!");
  fail_unless(Curl_llist_count(&asi->list) == 5, "wrong number of entries");

  if(Curl_peer_create(curl, scheme, "2.example.org", 8080, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi, "h3=\":8080\"\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(2) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 6, "wrong number of entries");

  if(Curl_peer_create(curl, scheme, "3.example.org", 8080, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.com:8080\", "
                             "h3=\"yesyes.com:8080\"\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(3) failed!");
  /* that one should make two entries */
  fail_unless(Curl_llist_count(&asi->list) == 8, "wrong number of entries");

  if(Curl_peer_create(curl, scheme, "example.org", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.com:443\"; ma = 120;\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(4) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 9, "wrong number of entries");

  /* quoted 'ma' value */
  if(Curl_peer_create(curl, scheme, "example.net", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.net:443\"; ma=\"180\";\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(5) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 10, "wrong number of entries");

  if(Curl_peer_create(curl, scheme, "curl.se", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\":443\"; ma=180, h3=\":443\"; "
                             "persist = \"1\"; ma = 120;\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(6) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 12, "wrong number of entries");

  /* clear that one again and decrease the counter */
  result = Curl_altsvc_parse(curl, asi, "clear;\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(7) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 10, "wrong number of entries");

  result = Curl_altsvc_parse(curl, asi,
                             "h2=\":443\", h3=\":443\"; "
                             "persist = \"1\"; ma = 120;\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(6) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 12, "wrong number of entries");

  /* clear - without semicolon */
  result = Curl_altsvc_parse(curl, asi, "clear\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(7) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 10, "wrong number of entries");

  /* only a non-existing alpn */
  if(Curl_peer_create(curl, scheme, "5.example.net", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h6=\"example.net:443\"; ma=\"180\";\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(8) failed!");

  /* missing quote in alpn host */
  if(Curl_peer_create(curl, scheme, "6.example.net", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.net:443,; ma=\"180\";\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(9) failed!");

  /* missing port in hostname */
  if(Curl_peer_create(curl, scheme, "7.example.net", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.net\"; ma=\"180\";\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(10) failed!");

  /* illegal port in hostname */
  if(Curl_peer_create(curl, scheme, "8.example.net", 80, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.net:70000\"; ma=\"180\";\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(11) failed!");

  if(Curl_peer_create(curl, scheme, "test.se", 443, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"test2.se:443\"; ma=\"180 \" ; unknown=2, "
                             "h2=\"test3.se:443\"; ma = 120;\r\n",
                             origin, ALPN_h2);
  fail_if(result, "Curl_altsvc_parse(12) failed!");

  /* Unknown extension parameters must not hide later known parameters. */
  if(Curl_peer_create(curl, scheme, "params.example", 443, &origin))
    goto fail;
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\":443\"; long-extension-parameter=token; "
                             "ext=token; "
                             "quoted=\"a;\\\"b\"; ma=120; persist=1\r\n",
                             origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(13) failed!");
  if(!Curl_altsvc_lookup(asi, origin, ALPN_h1, &dstentry,
                         CURLALTSVC_H2, &same_destination)) {
    fail_unless(FALSE, "alt-svc entry not found");
    goto fail;
  }
  fail_unless(dstentry->expires == 1548369261 + 120,
              "unknown parameters hid ma");
  fail_unless(dstentry->persist, "unknown parameters hid persist");
  fail_unless(same_destination, "wrong alt-svc destination");

  result = Curl_altsvc_parse(curl, asi, "clear\r\n", origin, ALPN_h1);
  fail_if(result, "Curl_altsvc_parse(14) failed!");

  Curl_altsvc_save(curl, asi, outname);

  /* RFC 7838 section 3: the protocol-id is a token where octets not
     allowed in a token are percent-encoded, so "http%2F1.1" is the
     conforming spelling of "http/1.1". See issue #23654. */
  {
    static const struct {
      const char *header;
      enum alpnid expected;
    } cases[] = {
      { "http%2F1.1=\":8080\"\r\n", ALPN_h1 },
      /* Noncanonical spellings are tolerated by the URL decoder. */
      { "http%2f1.1=\":8080\"\r\n", ALPN_h1 },
      { "%68%32=\":8080\"\r\n", ALPN_h2 },
      { "http%2G1.1=\":8080\"\r\n", ALPN_none },
      { "http%2=\":8080\"\r\n", ALPN_none },
      { "http%=\":8080\"\r\n", ALPN_none },
      { "h2%00=\":8080\"\r\n", ALPN_none },
      { "%00h2=\":8080\"\r\n", ALPN_none },
      { "h2%1F=\":8080\"\r\n", ALPN_none },
      { "=\":8080\"\r\n", ALPN_none },
      { "  =\":8080\"\r\n", ALPN_none },
      { "http%2G1.1=\":8443\", h2=\":8080\"\r\n", ALPN_h2 },
      { "h2%00=\":8443\", h2=\":8080\"\r\n", ALPN_h2 },
      { "h2%1F=\":8443\", http%2F1.1=\":8080\"\r\n", ALPN_h1 },
      { "h2=\":8080\", h2%00=\":8443\"\r\n", ALPN_h2 }
    };
    size_t i;

    if(Curl_peer_create(curl, scheme, "percent.example", 443, &origin))
      goto fail;
    for(i = 0; i < CURL_ARRAYSIZE(cases); i++) {
      bool found;

      /* Each case starts without an entry for this origin. */
      result = Curl_altsvc_parse(curl, asi, "clear\r\n", origin, ALPN_h1);
      fail_if(result, "Curl_altsvc_parse(clear) failed!");
      if(result)
        goto fail;
      result = Curl_altsvc_parse(curl, asi, cases[i].header, origin, ALPN_h1);
      fail_if(result, cases[i].header);
      if(result)
        goto fail;
      found = Curl_altsvc_lookup(asi, origin, ALPN_h1, &dstentry,
                                 CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3,
                                 &same_destination);
      fail_unless(found == (cases[i].expected != ALPN_none), cases[i].header);
      if(found) {
        fail_unless(dstentry->dst.alpnid == cases[i].expected,
                    cases[i].header);
        fail_unless(dstentry->dst.port == 8080, cases[i].header);
      }
    }
  }

fail:
  curl_easy_cleanup(curl);
  Curl_altsvc_cleanup(&asi);
  Curl_peer_unlink(&origin);
#endif

  UNITTEST_END(curl_global_cleanup())
}
