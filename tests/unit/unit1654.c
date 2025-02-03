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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetchcheck.h"

#include "urldata.h"
#include "altsvc.h"

static FETCHcode
unit_setup(void)
{
  return FETCHE_OK;
}

static void
unit_stop(void)
{
  fetch_global_cleanup();
}

UNITTEST_START
#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_ALTSVC)
{
  char outname[256];
  FETCH *fetch;
  FETCHcode result;
  struct altsvcinfo *asi = Fetch_altsvc_init();
  abort_if(!asi, "Fetch_altsvc_i");
  result = Fetch_altsvc_load(asi, arg);
  if (result)
  {
    fail_if(result, "Fetch_altsvc_load");
    goto fail;
  }
  fetch_global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fail_if(!fetch, "fetch_easy_init");
    goto fail;
  }
  fail_unless(Fetch_llist_count(&asi->list) == 4, "wrong number of entries");
  msnprintf(outname, sizeof(outname), "%s-out", arg);

  result = Fetch_altsvc_parse(fetch, asi, "h2=\"example.com:8080\"\r\n",
                             ALPN_h1, "example.org", 8080);
  fail_if(result, "Fetch_altsvc_parse() failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 5, "wrong number of entries");

  result = Fetch_altsvc_parse(fetch, asi, "h3=\":8080\"\r\n",
                             ALPN_h1, "2.example.org", 8080);
  fail_if(result, "Fetch_altsvc_parse(2) failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 6, "wrong number of entries");

  result = Fetch_altsvc_parse(fetch, asi,
                             "h2=\"example.com:8080\", h3=\"yesyes.com\"\r\n",
                             ALPN_h1, "3.example.org", 8080);
  fail_if(result, "Fetch_altsvc_parse(3) failed!");
  /* that one should make two entries */
  fail_unless(Fetch_llist_count(&asi->list) == 8, "wrong number of entries");

  result = Fetch_altsvc_parse(fetch, asi,
                             "h2=\"example.com:443\"; ma = 120;\r\n",
                             ALPN_h2, "example.org", 80);
  fail_if(result, "Fetch_altsvc_parse(4) failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 9, "wrong number of entries");

  /* quoted 'ma' value */
  result = Fetch_altsvc_parse(fetch, asi,
                             "h2=\"example.net:443\"; ma=\"180\";\r\n",
                             ALPN_h2, "example.net", 80);
  fail_if(result, "Fetch_altsvc_parse(4) failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 10, "wrong number of entries");

  result =
      Fetch_altsvc_parse(fetch, asi,
                        "h2=\":443\", h3=\":443\"; ma = 120; persist = 1\r\n",
                        ALPN_h1, "fetch.se", 80);
  fail_if(result, "Fetch_altsvc_parse(5) failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 12, "wrong number of entries");

  /* clear that one again and decrease the counter */
  result = Fetch_altsvc_parse(fetch, asi, "clear;\r\n",
                             ALPN_h1, "fetch.se", 80);
  fail_if(result, "Fetch_altsvc_parse(6) failed!");
  fail_unless(Fetch_llist_count(&asi->list) == 10, "wrong number of entries");

  Fetch_altsvc_save(fetch, asi, outname);

  fetch_easy_cleanup(fetch);
fail:
  Fetch_altsvc_cleanup(&asi);
}
#endif
UNITTEST_STOP
