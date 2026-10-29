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
 * is made for (CURLOPT_COOKIE_SITE) and the request host, and
 * Curl_cookie_site_ok(): the check of the site string itself. */

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)

struct t1924_case {
  const char *site;
  const char *host;
  bool secure;
  bool same;
};

struct t1924_site {
  const char *site;
  bool ok;
};

static CURLcode test_unit1924(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const struct t1924_case cases[] = {
    /* the host of the site and subdomains of it */
    { "http://example.com", "example.com", FALSE, TRUE },
    { "http://example.com", "www.example.com", FALSE, TRUE },
    { "https://example.com", "a.b.example.com", TRUE, TRUE },
    { "http://Example.COM", "WWW.example.com", FALSE, TRUE },
    { "HTTP://example.com", "example.com", FALSE, TRUE },
    /* a suffix that is not a subdomain */
    { "http://example.com", "notexample.com", FALSE, FALSE },
    { "http://example.com", "example.com.evil", FALSE, FALSE },
    { "http://example.com", "example.org", FALSE, FALSE },
    /* a parent domain is another site, the site is used as given */
    { "http://www.example.com", "example.com", FALSE, FALSE },
    /* trailing dots are ignored */
    { "http://example.com.", "example.com", FALSE, TRUE },
    { "http://example.com", "www.example.com.", FALSE, TRUE },
    /* the scheme must match */
    { "https://example.com", "example.com", TRUE, TRUE },
    { "https://example.com", "www.example.com", FALSE, FALSE },
    { "http://example.com", "example.com", TRUE, FALSE },
    /* IP addresses only match exactly */
    { "http://127.0.0.1", "127.0.0.1", FALSE, TRUE },
    { "http://0.0.1", "127.0.0.1", FALSE, FALSE },
    { "http://[::1]", "::1", FALSE, TRUE },
    { "https://[::1]", "::1", TRUE, TRUE },
    { "http://[::1]", "::2", FALSE, FALSE },
    /* not a site */
    { "", "example.com", FALSE, FALSE },
    { "https://", "example.com", TRUE, FALSE },
    { "example.com", "example.com", FALSE, FALSE },
    { "ftp://example.com", "example.com", FALSE, FALSE },
    { "http://example.com", "", FALSE, FALSE },
    { "http://.", "example.com", FALSE, FALSE }
  };
  static const struct t1924_site sites[] = {
    { "http://example.com", TRUE },
    { "https://example.com", TRUE },
    { "HTTPS://Example.COM.", TRUE },
    { "https://a-b_c.example.com", TRUE },
    { "https://127.0.0.1", TRUE },
    { "https://[::1]", TRUE },
    { "https://[fe80::1%25eth0]", FALSE },
    { "https://[::1", FALSE },
    { "https://[::1]x", FALSE },
    { "https://example.com:8443", FALSE },
    { "https://example.com/", FALSE },
    { "https://example.com/path", FALSE },
    { "https://example.com;x", FALSE },
    { "https://exa mple.com", FALSE },
    { "https://.example.com", FALSE },
    { "https://-example.com", FALSE },
    { "https://", FALSE },
    { "http://", FALSE },
    { "example.com", FALSE },
    { "ftp://example.com", FALSE },
    { "ws://example.com", FALSE },
    { "", FALSE }
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

  for(i = 0; i < CURL_ARRAYSIZE(sites); i++) {
    const struct t1924_site *c = &sites[i];
    bool ok = Curl_cookie_site_ok(c->site);
    if(ok != c->ok) {
      curl_mfprintf(stderr, "site %zu: '%s': got %d, expected %d\n",
                    i, c->site, (int)ok, (int)c->ok);
      fail_unless(ok == c->ok, "site check mismatch");
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
