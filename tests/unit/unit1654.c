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

#include "urldata.h"
#include "altsvc.h"

static CURLcode
unit_setup(void)
{
  return CURLE_OK;
}

static void
unit_stop(void)
{
  curl_global_cleanup();
}

UNITTEST_START
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_ALTSVC)
{
  char outname[256];
  CURL *curl;
  CURLcode result;
  struct altsvcinfo *asi = Curl_altsvc_init();
  abort_if(!asi, "Curl_altsvc_i");
  result = Curl_altsvc_load(asi, arg);
  if(result) {
    fail_if(result, "Curl_altsvc_load");
    goto fail;
  }
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    fail_if(!curl, "curl_easy_init");
    goto fail;
  }
  fail_unless(Curl_llist_count(&asi->list) == 4, "wrong number of entries");
  msnprintf(outname, sizeof(outname), "%s-out", arg);

  result = Curl_altsvc_parse(curl, asi, "h2=\"example.com:8080\"\r\n",
                             ALPN_h1, "example.org", 8080);
  fail_if(result, "Curl_altsvc_parse() failed!");
  fail_unless(Curl_llist_count(&asi->list) == 5, "wrong number of entries");

  result = Curl_altsvc_parse(curl, asi, "h3=\":8080\"\r\n",
                             ALPN_h1, "2.example.org", 8080);
  fail_if(result, "Curl_altsvc_parse(2) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 6, "wrong number of entries");

  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.com:8080\", h3=\"yesyes.com\"\r\n",
                             ALPN_h1, "3.example.org", 8080);
  fail_if(result, "Curl_altsvc_parse(3) failed!");
  /* that one should make two entries */
  fail_unless(Curl_llist_count(&asi->list) == 8, "wrong number of entries");

  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.com:443\"; ma = 120;\r\n",
                             ALPN_h2, "example.org", 80);
  fail_if(result, "Curl_altsvc_parse(4) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 9, "wrong number of entries");

  /* quoted 'ma' value */
  result = Curl_altsvc_parse(curl, asi,
                             "h2=\"example.net:443\"; ma=\"180\";\r\n",
                             ALPN_h2, "example.net", 80);
  fail_if(result, "Curl_altsvc_parse(4) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 10, "wrong number of entries");

  result =
    Curl_altsvc_parse(curl, asi,
                      "h2=\":443\", h3=\":443\"; ma = 120; persist = 1\r\n",
                      ALPN_h1, "curl.se", 80);
  fail_if(result, "Curl_altsvc_parse(5) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 12, "wrong number of entries");

  /* clear that one again and decrease the counter */
  result = Curl_altsvc_parse(curl, asi, "clear;\r\n",
                             ALPN_h1, "curl.se", 80);
  fail_if(result, "Curl_altsvc_parse(6) failed!");
  fail_unless(Curl_llist_count(&asi->list) == 10, "wrong number of entries");

  Curl_altsvc_save(curl, asi, outname);

  curl_easy_cleanup(curl);
fail:
  Curl_altsvc_cleanup(&asi);
}
#endif
UNITTEST_STOP
