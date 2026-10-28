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
#include "cookie.h"

/* Test cookie_same_site(): the same-site check between the site a request
 * is made for (CURLOPT_COOKIE_SITE) and the request host. */

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)

struct t1924_case {
  const char *site;
  const char *host;
  bool secure;
  bool same;
};

static CURLcode test_unit1924(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const struct t1924_case cases[] = {
    /* the site itself and subdomains */
    { "example.com", "example.com", FALSE, TRUE },
    { "example.com", "www.example.com", FALSE, TRUE },
    { "example.com", "a.b.example.com", TRUE, TRUE },
    { "Example.COM", "WWW.example.com", FALSE, TRUE },
    /* a suffix that is not a subdomain */
    { "example.com", "notexample.com", FALSE, FALSE },
    { "example.com", "example.com.evil", FALSE, FALSE },
    { "example.com", "example.org", FALSE, FALSE },
    /* a parent domain is another site */
    { "www.example.com", "example.com", FALSE, FALSE },
    /* trailing dots are ignored */
    { "example.com.", "example.com", FALSE, TRUE },
    { "example.com", "www.example.com.", FALSE, TRUE },
    /* schemeful same-site */
    { "https://example.com", "example.com", TRUE, TRUE },
    { "https://example.com", "www.example.com", FALSE, FALSE },
    { "http://example.com", "example.com", FALSE, TRUE },
    { "http://example.com", "example.com", TRUE, FALSE },
    { "https://example.com/", "example.com", TRUE, TRUE },
    { "https://example.com/path", "example.com", TRUE, TRUE },
    /* ports are not part of a site */
    { "https://example.com:8443", "example.com", TRUE, TRUE },
    { "example.com:8080", "www.example.com", FALSE, TRUE },
    { "http://127.0.0.1:8000", "127.0.0.1", FALSE, TRUE },
    { "[::1]:8000", "::1", FALSE, TRUE },
    /* IP addresses only match exactly */
    { "127.0.0.1", "127.0.0.1", FALSE, TRUE },
    { "0.0.1", "127.0.0.1", FALSE, FALSE },
    { "[::1]", "::1", FALSE, TRUE },
    { "https://[::1]", "::1", TRUE, TRUE },
    { "[::1]", "::2", FALSE, FALSE },
    /* junk */
    { "", "example.com", FALSE, FALSE },
    { "https://", "example.com", TRUE, FALSE },
    { "example.com", "", FALSE, FALSE },
    { ".", "example.com", FALSE, FALSE }
  };
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(cases); i++) {
    const struct t1924_case *c = &cases[i];
    bool same = cookie_same_site(c->site, c->host, c->secure);
    if(same != c->same) {
      curl_mfprintf(stderr, "case %zu: site '%s' host '%s' secure=%d: "
                    "got %d, expected %d\n", i, c->site, c->host,
                    (int)c->secure, (int)same, (int)c->same);
      fail_unless(same == c->same, "same-site mismatch");
    }
  }

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit1924(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since cookies are disabled");
  UNITTEST_END_SIMPLE
}

#endif
