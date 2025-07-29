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
#include "http.h"
#include "http1.h"
#include "curl_trc.h"

#ifndef CURL_DISABLE_HTTP
static void check_eq(const char *s, const char *exp_s, const char *name)
{
  if(s && exp_s) {
    if(strcmp(s, exp_s)) {
      curl_mfprintf(stderr, "expected %s: '%s' but got '%s'\n",
                    name, exp_s, s);
      fail("unexpected req component");
    }
  }
  else if(!s && exp_s) {
    curl_mfprintf(stderr, "expected %s: '%s' but got NULL\n", name, exp_s);
    fail("unexpected req component");
  }
  else if(s && !exp_s) {
    curl_mfprintf(stderr, "expected %s: NULL but got '%s'\n", name, s);
    fail("unexpected req component");
  }
}

struct tcase {
  const char **input;
  const char *default_scheme;
  const char *method;
  const char *scheme;
  const char *authority;
  const char *path;
  size_t header_count;
  size_t input_remain;
};

static void parse_success(const struct tcase *t)
{
  struct h1_req_parser p;
  const char *buf;
  size_t buflen, i, in_len, in_consumed;
  CURLcode err;
  ssize_t nread;

  Curl_h1_req_parse_init(&p, 1024);
  in_len = in_consumed = 0;
  for(i = 0; t->input[i]; ++i) {
    buf = t->input[i];
    buflen = strlen(buf);
    in_len += buflen;
    nread = Curl_h1_req_parse_read(&p, buf, buflen, t->default_scheme,
                                   0, &err);
    if(nread < 0) {
      curl_mfprintf(stderr, "got err %d parsing: '%s'\n", err, buf);
      fail("error consuming");
    }
    in_consumed += (size_t)nread;
    if((size_t)nread != buflen) {
      if(!p.done) {
        curl_mfprintf(stderr, "only %zd/%zu consumed for: '%s'\n",
                      nread, buflen, buf);
        fail("not all consumed");
      }
    }
  }

  fail_if(!p.done, "end not detected");
  fail_if(!p.req, "not request created");
  if(t->input_remain != (in_len - in_consumed)) {
    curl_mfprintf(stderr, "expected %zu input bytes to remain, but got %zu\n",
                  t->input_remain, in_len - in_consumed);
    fail("unexpected input consumption");
  }
  if(p.req) {
    check_eq(p.req->method, t->method, "method");
    check_eq(p.req->scheme, t->scheme, "scheme");
    check_eq(p.req->authority, t->authority, "authority");
    check_eq(p.req->path, t->path, "path");
    if(Curl_dynhds_count(&p.req->headers) != t->header_count) {
      curl_mfprintf(stderr, "expected %zu headers but got %zu\n",
                    t->header_count, Curl_dynhds_count(&p.req->headers));
      fail("unexpected req header count");
    }
  }

  Curl_h1_req_parse_free(&p);
}
#endif

static CURLcode test_unit2603(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifndef CURL_DISABLE_HTTP
  static const char *T1_INPUT[] = {
    "GET /path HTTP/1.1\r\nHost: test.curl.se\r\n\r\n",
    NULL,
  };
  static const struct tcase TEST1a = {
    T1_INPUT, NULL, "GET", NULL, NULL, "/path", 1, 0
  };
  static const struct tcase TEST1b = {
    T1_INPUT, "https", "GET", "https", NULL, "/path", 1, 0
  };

  static const char *T2_INPUT[] = {
    "GET /path HTT",
    "P/1.1\r\nHost: te",
    "st.curl.se\r\n\r",
    "\n12345678",
    NULL,
  };
  static const struct tcase TEST2 = {
    T2_INPUT, NULL, "GET", NULL, NULL, "/path", 1, 8
  };

  static const char *T3_INPUT[] = {
    "GET ftp://ftp.curl.se/xxx?a=2 HTTP/1.1\r\nContent-Length: 0\r",
    "\nUser-Agent: xxx\r\n\r\n",
    NULL,
  };
  static const struct tcase TEST3a = {
    T3_INPUT, NULL, "GET", "ftp", "ftp.curl.se", "/xxx?a=2", 2, 0
  };

  static const char *T4_INPUT[] = {
    "CONNECT ftp.curl.se:123 HTTP/1.1\r\nContent-Length: 0\r\n",
    "User-Agent: xxx\r\n",
    "nothing:  \r\n\r\n\n\n",
    NULL,
  };
  static const struct tcase TEST4a = {
    T4_INPUT, NULL, "CONNECT", NULL, "ftp.curl.se:123", NULL, 3, 2
  };

  static const char *T5_INPUT[] = {
    "OPTIONS * HTTP/1.1\r\nContent-Length: 0\r\nBlabla: xxx.yyy\r",
    "\n\tzzzzzz\r\n\r\n",
    "123",
    NULL,
  };
  static const struct tcase TEST5a = {
    T5_INPUT, NULL, "OPTIONS", NULL, NULL, "*", 2, 3
  };

  static const char *T6_INPUT[] = {
    "PUT /path HTTP/1.1\nHost: test.curl.se\n\n123",
    NULL,
  };
  static const struct tcase TEST6a = {
    T6_INPUT, NULL, "PUT", NULL, NULL, "/path", 1, 3
  };

  parse_success(&TEST1a);
  parse_success(&TEST1b);
  parse_success(&TEST2);
  parse_success(&TEST3a);
  parse_success(&TEST4a);
  parse_success(&TEST5a);
  parse_success(&TEST6a);
#endif

  UNITTEST_END_SIMPLE
}
