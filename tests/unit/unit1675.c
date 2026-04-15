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
#include "urlapi-int.h"
#include "curlx/dynbuf.h"

static CURLcode test_unit1675(const char *arg)
{
  (void)arg;
  UNITTEST_BEGIN_SIMPLE

    /* Test ipv4_normalize */
  {
    struct dynbuf host;
    int fails = 0;
    unsigned int i;
    struct ipv4_test {
      const char *in;
      const char *out;
    };
    const struct ipv4_test tests[] = {
      {"0x.0x.0x.0x", NULL}, /* invalid hex */
      {"0x.0x.0x", NULL}, /* invalid hex */
      {"0x.0x", NULL}, /* invalid hex */
      {"0x", NULL}, /* invalid hex */
      {"0", "0.0.0.0"},
      {"00", "0.0.0.0"},
      {"00000000000", "0.0.0.0"},
      {"127.0.0.1", "127.0.0.1"},
      {"0177.0.0.1", "127.0.0.1"},
      {"00177.0.0.1", "127.0.0.1"},
      {"0x7f.0.0.1", "127.0.0.1"},
      {"0x07f.0.0.1", "127.0.0.1"},
      {"1", "0.0.0.1"},
      {"010", "0.0.0.8"},
      {"001", "0.0.0.1"},
      {"127", "0.0.0.127"},
      {"127.1", "127.0.0.1"},
      {"127.0.1", "127.0.0.1"},
      {"1.16777215", "1.255.255.255"},
      {"1.16777216", NULL}, /* overflow */
      {"1.1.65535", "1.1.255.255"},
      {"1.1.65536", NULL}, /* overflow */
      {"0x7f000001", "127.0.0.1"},
      {"0x7F000001", "127.0.0.1"},
      {"0x7g000001", NULL}, /* bad hex */
      {"2130706433", "127.0.0.1"},
      {"017700000001", "127.0.0.1"},
      {"000000000017700000001", "127.0.0.1"},
      {"192.168.0.1", "192.168.0.1"},
      {"0300.0250.0000.0001", "192.168.0.1"},
      {"0xc0.0xa8.0.1", "192.168.0.1"},
      {"0xc0a80001", "192.168.0.1"},
      {"3232235521", "192.168.0.1"},
      {"4294967294", "255.255.255.254"},
      {"4294967295", "255.255.255.255"},
      {"037777777777", "255.255.255.255"},
      {"0xFFFFFFFF", "255.255.255.255"},
      {"0xFFFFFfff", "255.255.255.255"},
      {"1.2.3.4.5", NULL}, /* too many parts */
      {"256.0.0.1", NULL}, /* overflow */
      {"1.256.0.1", NULL}, /* overflow */
      {"1.1.256.1", NULL}, /* overflow */
      {"1.0.0.256", NULL}, /* overflow */
      {"0x100.0.0.1", NULL}, /* overflow */
      {"1.0x100.0.1", NULL}, /* overflow */
      {"1.1.0x100.1", NULL}, /* overflow */
      {"1.1.1.0x100", NULL}, /* overflow */
      {"0400.0.0.1", NULL}, /* overflow */
      {"4.0400.0.1", NULL}, /* overflow */
      {"4.4.0400.1", NULL}, /* overflow */
      {"4.4.4.0400", NULL}, /* overflow */
      {"4294967296", NULL}, /* overflow */
      {"040000000000", NULL}, /* overflow */
      {"0x100000000", NULL}, /* overflow */
      {"1.2.3.-4", NULL}, /* negative */
      {"1.2.-3.4", NULL}, /* negative */
      {"1.-2.3.4", NULL}, /* negative */
      {"-1.2.3.4", NULL}, /* negative */
      {"-12", NULL}, /* negative */
      {"-12.1", NULL}, /* negative */
      {"-12.2.3", NULL}, /* negative */
      {" 1.2.3.4", NULL}, /* space */
      {"1. 2.3.4", NULL}, /* space */
      {"1.2. 3.4", NULL}, /* space */
      {"1.2.3. 4", NULL}, /* space */
    };

    curlx_dyn_init(&host, 256);
    for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
      int rc;
      curlx_dyn_reset(&host);
      if(curlx_dyn_add(&host, tests[i].in)) {
        return CURLE_OUT_OF_MEMORY;
      }
      rc = ipv4_normalize(&host);
      if(tests[i].out) {
        if((rc != HOST_IPV4) ||
           strcmp(curlx_dyn_ptr(&host), tests[i].out)) {
          curl_mfprintf(stderr, "ipv4_normalize('%s') failed: "
                        "expected '%s', got '%s'\n",
                        tests[i].in, tests[i].out, curlx_dyn_ptr(&host));
          fails++;
        }
      }
      else {
        if(rc == HOST_IPV4) {
          curl_mfprintf(stderr, "ipv4_normalize('%s') succeeded unexpectedly:"
                        " got '%s'\n",
                        tests[i].in, curlx_dyn_ptr(&host));
          fails++;
        }
      }
    }
    curlx_dyn_free(&host);
    abort_if(fails, "ipv4_normalize tests failed");
  }

  /* Test urlencode_str */
  {
    struct dynbuf out;
    int fails = 0;
    unsigned int i;
    struct urlencode_test {
      const char *in;
      bool relative;
      unsigned int query;
      const char *out;
    };
    const struct urlencode_test tests[] = {
      {"http://leave\x01/hello\x01world", FALSE, QUERY_NO,
       "http://leave\x01/hello%01world"},
      {"http://leave/hello\x01world", FALSE, QUERY_NO,
       "http://leave/hello%01world"},
      {"http://le ave/hello\x01world", FALSE, QUERY_NO,
       "http://le ave/hello%01world"},
      {"hello\x01world", TRUE, QUERY_NO, "hello%01world"},
      {"hello\xf0world", TRUE, QUERY_NO, "hello%F0world"},
      {"hello world", TRUE, QUERY_NO, "hello%20world"},
      {"hello%20world", TRUE, QUERY_NO, "hello%20world"},
      {"hello world", TRUE, QUERY_YES, "hello+world"},
      {"a+b c", TRUE, QUERY_NO, "a+b%20c"},
      {"a%20b%20c", TRUE, QUERY_NO, "a%20b%20c"},
      {"a%aab%aac", TRUE, QUERY_NO, "a%AAb%AAc"},
      {"a%aab%AAc", TRUE, QUERY_NO, "a%AAb%AAc"},
      {"w%w%x", TRUE, QUERY_NO, "w%w%x"},
      {"w%wf%xf", TRUE, QUERY_NO, "w%wf%xf"},
      {"w%fw%fw", TRUE, QUERY_NO, "w%fw%fw"},
      {"a+b c", TRUE, QUERY_YES, "a+b+c"},
      {"/foo/bar", TRUE, QUERY_NO, "/foo/bar"},
      {"/foo/bar", TRUE, QUERY_YES, "/foo/bar"},
      {"/foo/ bar", TRUE, QUERY_NO, "/foo/%20bar"},
      {"/foo/ bar", TRUE, QUERY_YES, "/foo/+bar"},
      {"~-._", TRUE, QUERY_NO, "~-._"},
      {"~-._", TRUE, QUERY_YES, "~-._"},
      {"foo bar?foo bar", TRUE, QUERY_NO, "foo%20bar?foo%20bar"},
      {"foo bar?foo bar", TRUE, QUERY_NOT_YET, "foo%20bar?foo+bar"},
    };

    curlx_dyn_init(&out, 256);
    for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
      CURLUcode uc;
      curlx_dyn_reset(&out);
      uc = urlencode_str(&out, tests[i].in, strlen(tests[i].in),
                         tests[i].relative, tests[i].query);
      if(uc || strcmp(curlx_dyn_ptr(&out), tests[i].out)) {
        curl_mfprintf(stderr, "urlencode_str('%s', query=%d) failed:"
                      " expected '%s', got '%s'\n",
                      tests[i].in, tests[i].query, tests[i].out,
                      uc ? "error" : curlx_dyn_ptr(&out));
        fails++;
      }
    }
    curlx_dyn_free(&out);
    abort_if(fails, "urlencode_str tests failed");
  }

  /* Test ipv6_parse */
  {
    struct Curl_URL u;
    int fails = 0;
    unsigned int i;
    struct ipv6_test {
      const char *in;
      const char *out_host;
      const char *out_zone;
    };
    const struct ipv6_test tests[] = {
      {"[::1]", "[::1]", NULL},
      {"[fe80::1%eth0]", "[fe80::1]", "eth0"},
      {"[fe80::1%25eth0]", "[fe80::1]", "eth0"},
      {"[::1", NULL, NULL}, /* missing bracket */
      {"[]", NULL, NULL}, /* empty */
    };

    for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
      CURLUcode uc;
      char hostname[256];
      memset(&u, 0, sizeof(u));
      curlx_strcopy(hostname, sizeof(hostname),
                    tests[i].in, strlen(tests[i].in));
      uc = ipv6_parse(&u, hostname, strlen(hostname));
      if(tests[i].out_host) {
        if(uc || strcmp(hostname, tests[i].out_host)) {
          curl_mfprintf(stderr, "ipv6_parse('%s') host failed:"
                        " expected '%s', got '%s'\n",
                        tests[i].in, tests[i].out_host,
                        uc ? "error" : hostname);
          fails++;
        }
        if(!uc && tests[i].out_zone) {
          if(!u.zoneid || strcmp(u.zoneid, tests[i].out_zone)) {
            curl_mfprintf(stderr, "ipv6_parse('%s') zone failed:"
                          " expected '%s', got '%s'\n",
                          tests[i].in, tests[i].out_zone,
                          u.zoneid ? u.zoneid : "(null)");
            fails++;
          }
        }
      }
      else {
        if(!uc) {
          curl_mfprintf(stderr, "ipv6_parse('%s') succeeded unexpectedly\n",
                        tests[i].in);
          fails++;
        }
      }
      curlx_free(u.host);
      curlx_free(u.zoneid);
    }
    abort_if(fails, "ipv6_parse tests failed");
  }

  /* Test parse_file */
  {
    CURLU *u;
    const char *path;
    size_t pathlen;
    int fails = 0;
    unsigned int i;
    struct file_test {
      const char *in;
      const char *out_path;
      bool fine;
    };
    const struct file_test tests[] = {
      {"file:///etc/hosts", "/etc/hosts", TRUE},
      {"file://localhost/etc/hosts", "/etc/hosts", TRUE},
      {"file://apple/etc/hosts", "/etc/hosts", FALSE},
#ifdef _WIN32
      {"file:///c:/windows/system32", "c:/windows/system32", TRUE},
      {"file://localhost/c:/windows/system32", "c:/windows/system32", TRUE},
#endif
    };

    for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
      CURLUcode uc;
      u = curl_url();
      if(!u)
        return CURLE_OUT_OF_MEMORY;

      uc = parse_file(tests[i].in, strlen(tests[i].in), u, &path, &pathlen);
      if(!tests[i].fine && !uc) {
        curl_mfprintf(stderr, "Unexpectedly fine for input '%s'\n",
                      tests[i].in);
        fails++;
      }
      if(tests[i].fine &&
         (uc ||
          strncmp(path, tests[i].out_path, pathlen) ||
          strlen(tests[i].out_path) != pathlen)) {
        curl_mfprintf(stderr, "parse_file('%s') failed:"
                      " expected path '%s'; got path '%.*s'\n",
                      tests[i].in, tests[i].out_path,
                      (int)pathlen, path);
        fails++;
      }
      curl_url_cleanup(u);
    }
    abort_if(fails, "parse_file tests failed");
  }

  /* Test same origin check */
  {
    CURLU *base, *href;
    int fails = 0;
    unsigned int i;
    bool match;
    struct origin_test {
      const char *base;
      const char *scheme;
      const char *host;
      const char *port;
      const char *path;
      bool expect_match;
    };
    const struct origin_test tests[] = {
      {"http://host:123/x", "http", "host", "123", "/y", TRUE},
      {"http://host:123/x", NULL, "host", "123", "/y", TRUE},
      {"http://host:123/x", NULL, NULL, NULL, "/y", TRUE},
      {"http://host:80/x", "http", "host", "123", "/y", FALSE},
      {"http://host:80/x", "http", "host", NULL, "/y", TRUE},
      {"http://host/x", "http", "host", "80", "/y", TRUE},
      {"http://host:123/x", "https", "host", "123", "/y", FALSE},
      {"https://host/x", "http", "host", "443", "/y", FALSE},
      {"https://host/x", "https", "host", "443", "/y", TRUE},
    };

    for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
      CURLUcode uc;
      base = curl_url();
      href = curl_url();
      if(!base || !href)
        return CURLE_OUT_OF_MEMORY;
      uc = curl_url_set(base, CURLUPART_URL, tests[i].base, 0);
      if(uc) {
        curl_mfprintf(stderr, "failed to parse %d base %s -> %d\n", i,
                      tests[i].base, uc);
        fails++;
        goto loop_end;
      }
      if(tests[i].scheme)
        uc = curl_url_set(href, CURLUPART_SCHEME, tests[i].scheme, 0);
      if(!uc && tests[i].host)
        uc = curl_url_set(href, CURLUPART_HOST, tests[i].host, 0);
      if(!uc && tests[i].port)
        uc = curl_url_set(href, CURLUPART_PORT, tests[i].port, 0);
      if(!uc && tests[i].path)
        uc = curl_url_set(href, CURLUPART_PATH, tests[i].path, 0);
      if(uc) {
        curl_mfprintf(stderr, "failed to parse %d href %s://%s:%s%s -> %d\n",
                      i, tests[i].scheme, tests[i].host, tests[i].port,
                      tests[i].path, uc);
        fails++;
        goto loop_end;
      }

      match = curl_url_same_origin(base, href);
      if(match != tests[i].expect_match) {
        curl_mfprintf(stderr, "ERROR: %d base %s and href %s://%s:%s%s %s\n",
                      i, tests[i].base, tests[i].scheme, tests[i].host,
                      tests[i].port, tests[i].path,
                      match ? "matched" : "did not match");
        fails++;
      }

loop_end:
      curl_url_cleanup(base);
      curl_url_cleanup(href);
    }
    abort_if(fails, "same_origin tests failed");
  }

  UNITTEST_END_SIMPLE
}
