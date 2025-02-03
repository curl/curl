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

/*
 * Note:
 *
 * Since the URL parser by default only accepts schemes that *this instance*
 * of libfetch supports, make sure that the test1560 file lists all the schemes
 * that this test will assume to be present!
 */

#include "test.h"
#if defined(USE_LIBIDN2) || defined(USE_WIN32_IDN) || defined(USE_APPLE_IDN)
#define USE_IDN
#endif

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h" /* LAST include file */

struct part
{
  FETCHUPart part;
  const char *name;
};

static int checkparts(FETCHU *u, const char *in, const char *wanted,
                      unsigned int getflags)
{
  int i;
  FETCHUcode rc;
  char buf[256];
  char *bufp = &buf[0];
  size_t len = sizeof(buf);
  struct part parts[] = {
      {FETCHUPART_SCHEME, "scheme"},
      {FETCHUPART_USER, "user"},
      {FETCHUPART_PASSWORD, "password"},
      {FETCHUPART_OPTIONS, "options"},
      {FETCHUPART_HOST, "host"},
      {FETCHUPART_PORT, "port"},
      {FETCHUPART_PATH, "path"},
      {FETCHUPART_QUERY, "query"},
      {FETCHUPART_FRAGMENT, "fragment"},
      {FETCHUPART_URL, NULL}};
  memset(buf, 0, sizeof(buf));

  for (i = 0; parts[i].name; i++)
  {
    char *p = NULL;
    size_t n;
    rc = fetch_url_get(u, parts[i].part, &p, getflags);
    if (!rc && p)
    {
      msnprintf(bufp, len, "%s%s", buf[0] ? " | " : "", p);
    }
    else
      msnprintf(bufp, len, "%s[%d]", buf[0] ? " | " : "", (int)rc);

    n = strlen(bufp);
    bufp += n;
    len -= n;
    fetch_free(p);
  }
  if (strcmp(buf, wanted))
  {
    fprintf(stderr, "in: %s\nwanted: %s\ngot:    %s\n", in, wanted, buf);
    return 1;
  }
  return 0;
}

struct redircase
{
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags;
  unsigned int setflags;
  FETCHUcode ucode;
};

struct setcase
{
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags;
  unsigned int setflags;
  FETCHUcode ucode; /* for the main URL set */
  FETCHUcode pcode; /* for updating parts */
};

struct setgetcase
{
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags; /* for setting the URL */
  unsigned int setflags; /* for updating parts */
  unsigned int getflags; /* for getting parts */
  FETCHUcode pcode;      /* for updating parts */
};

struct testcase
{
  const char *in;
  const char *out;
  unsigned int urlflags;
  unsigned int getflags;
  FETCHUcode ucode;
};

struct urltestcase
{
  const char *in;
  const char *out;
  unsigned int urlflags; /* pass to fetch_url() */
  unsigned int getflags; /* pass to fetch_url_get() */
  FETCHUcode ucode;
};

struct querycase
{
  const char *in;
  const char *q;
  const char *out;
  unsigned int urlflags; /* pass to fetch_url() */
  unsigned int qflags;   /* pass to fetch_url_get() */
  FETCHUcode ucode;
};

struct clearurlcase
{
  FETCHUPart part;
  const char *in;
  const char *out;
  FETCHUcode ucode;
};

static const struct testcase get_parts_list[] = {
    {"fetch.se",
     "[10] | [11] | [12] | [13] | fetch.se | [15] | / | [16] | [17]",
     FETCHU_GUESS_SCHEME, FETCHU_NO_GUESS_SCHEME, FETCHUE_OK},
    {"https://fetch.se:0/#",
     "https | [11] | [12] | [13] | fetch.se | 0 | / | [16] | ",
     0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://fetch.se/#",
     "https | [11] | [12] | [13] | fetch.se | [15] | / | [16] | ",
     0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://fetch.se/?#",
     "https | [11] | [12] | [13] | fetch.se | [15] | / |  | ",
     0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://fetch.se/?",
     "https | [11] | [12] | [13] | fetch.se | [15] | / |  | [17]",
     0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://fetch.se/?",
     "https | [11] | [12] | [13] | fetch.se | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"https://fetch.se/?#",
     "https | [11] | [12] | [13] | fetch.se | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"https://fetch.se/#  ",
     "https | [11] | [12] | [13] | fetch.se | [15] | / | [16] | %20%20",
     FETCHU_URLENCODE | FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {" ", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"1h://example.net", "", 0, 0, FETCHUE_BAD_SCHEME},
    {"..://example.net", "", 0, 0, FETCHUE_BAD_SCHEME},
    {"-ht://example.net", "", 0, 0, FETCHUE_BAD_SCHEME},
    {"+ftp://example.net", "", 0, 0, FETCHUE_BAD_SCHEME},
    {"hej.hej://example.net",
     "hej.hej | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"ht-tp://example.net",
     "ht-tp | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"ftp+more://example.net",
     "ftp+more | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"f1337://example.net",
     "f1337 | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"https://user@example.net?hello# space ",
     "https | user | [12] | [13] | example.net | [15] | / | hello | %20space%20",
     FETCHU_ALLOW_SPACE | FETCHU_URLENCODE, 0, FETCHUE_OK},
    {"https://test%test", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example.com%252f%40@example.net",
     "https | example.com%2f@ | [12] | [13] | example.net | [15] | / "
     "| [16] | [17]",
     0, FETCHU_URLDECODE, FETCHUE_OK},
#ifdef USE_IDN
    {"https://räksmörgås.se",
     "https | [11] | [12] | [13] | xn--rksmrgs-5wao1o.se | "
     "[15] | / | [16] | [17]",
     0, FETCHU_PUNYCODE, FETCHUE_OK},
    {"https://xn--rksmrgs-5wao1o.se",
     "https | [11] | [12] | [13] | räksmörgås.se | "
     "[15] | / | [16] | [17]",
     0, FETCHU_PUNY2IDN, FETCHUE_OK},
#else
    {"https://räksmörgås.se",
     "https | [11] | [12] | [13] | [30] | [15] | / | [16] | [17]",
     0, FETCHU_PUNYCODE, FETCHUE_OK},
#endif
    /* https://ℂᵤⓇℒ。𝐒🄴 */
    {"https://"
     "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4",
     "https | [11] | [12] | [13] | ℂᵤⓇℒ。𝐒🄴 | [15] |"
     " / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"https://"
     "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4",
     "https | [11] | [12] | [13] | "
     "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4 "
     "| [15] | / | [16] | [17]",
     0, FETCHU_URLENCODE, FETCHUE_OK},
    {"https://"
     "\xe2\x84\x82\xe1\xb5\xa4\xe2\x93\x87\xe2\x84\x92"
     "\xe3\x80\x82\xf0\x9d\x90\x92\xf0\x9f\x84\xb4",
     "https | [11] | [12] | [13] | "
     "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4 "
     "| [15] | / | [16] | [17]",
     0, FETCHU_URLENCODE, FETCHUE_OK},
    {"https://user@example.net?he l lo",
     "https | user | [12] | [13] | example.net | [15] | / | he+l+lo | [17]",
     FETCHU_ALLOW_SPACE, FETCHU_URLENCODE, FETCHUE_OK},
    {"https://user@example.net?he l lo",
     "https | user | [12] | [13] | example.net | [15] | / | he l lo | [17]",
     FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"https://exam{}[]ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam{ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam}ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam]ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam\\ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam$ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam'ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam\"ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam^ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam`ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam*ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam<ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam>ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam=ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://exam;ple.net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example,net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example&net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example+net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example(net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example)net", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://example.net/}",
     "https | [11] | [12] | [13] | example.net | [15] | /} | [16] | [17]",
     0, 0, FETCHUE_OK},

    /* blank user is blank */
    {"https://:password@example.net",
     "https |  | password | [13] | example.net | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    /* blank user + blank password */
    {"https://:@example.net",
     "https |  |  | [13] | example.net | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    /* user-only (no password) */
    {"https://user@example.net",
     "https | user | [12] | [13] | example.net | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
#ifndef FETCH_DISABLE_WEBSOCKETS
    {"ws://example.com/color/?green",
     "ws | [11] | [12] | [13] | example.com | [15] | /color/ | green |"
     " [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"wss://example.com/color/?green",
     "wss | [11] | [12] | [13] | example.com | [15] | /color/ | green |"
     " [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
#endif

    {"https://user:password@example.net/get?this=and#but frag then", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://user:password@example.net/get?this=and what", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://user:password@example.net/ge t?this=and-what", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://user:pass word@example.net/get?this=and-what", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://u ser:password@example.net/get?this=and-what", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"imap://user:pass;opt ion@server/path", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    /* no space allowed in scheme */
    {"htt ps://user:password@example.net/get?this=and-what", "",
     FETCHU_NON_SUPPORT_SCHEME | FETCHU_ALLOW_SPACE, 0, FETCHUE_BAD_SCHEME},
    {"https://user:password@example.net/get?this=and what",
     "https | user | password | [13] | example.net | [15] | /get | "
     "this=and what | [17]",
     FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"https://user:password@example.net/ge t?this=and-what",
     "https | user | password | [13] | example.net | [15] | /ge t | "
     "this=and-what | [17]",
     FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"https://user:pass word@example.net/get?this=and-what",
     "https | user | pass word | [13] | example.net | [15] | /get | "
     "this=and-what | [17]",
     FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"https://u ser:password@example.net/get?this=and-what",
     "https | u ser | password | [13] | example.net | [15] | /get | "
     "this=and-what | [17]",
     FETCHU_ALLOW_SPACE, 0, FETCHUE_OK},
    {"https://user:password@example.net/ge t?this=and-what",
     "https | user | password | [13] | example.net | [15] | /ge%20t | "
     "this=and-what | [17]",
     FETCHU_ALLOW_SPACE | FETCHU_URLENCODE, 0, FETCHUE_OK},
    {"[0:0:0:0:0:0:0:1]",
     "http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"[::1]",
     "http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"[::]",
     "http | [11] | [12] | [13] | [::] | [15] | / | [16] | [17]",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"https://[::1]",
     "https | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"user:moo@ftp.example.com/color/#green?no-red",
     "ftp | user | moo | [13] | ftp.example.com | [15] | /color/ | [16] | "
     "green?no-red",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ftp.user:moo@example.com/color/#green?no-red",
     "http | ftp.user | moo | [13] | example.com | [15] | /color/ | [16] | "
     "green?no-red",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
#ifdef _WIN32
    {"file:/C:\\programs\\foo",
     "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"file://C:\\programs\\foo",
     "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"file:///C:\\programs\\foo",
     "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"file://host.example.com/Share/path/to/file.txt",
     "file | [11] | [12] | [13] | host.example.com | [15] | "
     "//host.example.com/Share/path/to/file.txt | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
#endif
    {"https://example.com/color/#green?no-red",
     "https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | "
     "green?no-red",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com/color/#green#no-red",
     "https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | "
     "green#no-red",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com/color/?green#no-red",
     "https | [11] | [12] | [13] | example.com | [15] | /color/ | green | "
     "no-red",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com/#color/?green#no-red",
     "https | [11] | [12] | [13] | example.com | [15] | / | [16] | "
     "color/?green#no-red",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.#com/color/?green#no-red",
     "https | [11] | [12] | [13] | example. | [15] | / | [16] | "
     "com/color/?green#no-red",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://[ab.be:1]/x", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_BAD_IPV6},
    {"http://[ab.be]/x", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_BAD_IPV6},
    /* URL without host name */
    {"http://a:b@/x", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_NO_HOST},
    {"boing:80",
     "https | [11] | [12] | [13] | boing | 80 | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME | FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"http://[fd00:a41::50]:8080",
     "http | [11] | [12] | [13] | [fd00:a41::50] | 8080 | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://[fd00:a41::50]/",
     "http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://[fd00:a41::50]",
     "http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://[::1%252]:1234",
     "https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},

    /* here's "bad" zone id */
    {"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234",
     "https | [11] | [12] | [13] | [fe80::20c:29ff:fe9c:409b] | 1234 "
     "| / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://127.0.0.1:443",
     "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]",
     0, FETCHU_NO_DEFAULT_PORT, FETCHUE_OK},
    {"http://%3a:%3a@ex4mple/%3f+?+%3f+%23#+%23%3f%g7",
     "http | : | : | [13] | ex4mple | [15] | /?+ |  ? # | +#?%g7",
     0, FETCHU_URLDECODE, FETCHUE_OK},
    {"http://%3a:%3a@ex4mple/%3f?%3f%35#%35%3f%g7",
     "http | %3a | %3a | [13] | ex4mple | [15] | /%3f | %3f%35 | %35%3f%g7",
     0, 0, FETCHUE_OK},
    {"http://HO0_-st%41/",
     "http | [11] | [12] | [13] | HO0_-stA | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file://hello.html",
     "",
     0, 0, FETCHUE_BAD_FILE_URL},
    {"http://HO0_-st/",
     "http | [11] | [12] | [13] | HO0_-st | [15] | / | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"imap://user:pass;option@server/path",
     "imap | user | pass | option | server | [15] | /path | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"http://user:pass;option@server/path",
     "http | user | pass;option | [13] | server | [15] | /path | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file:/hello.html",
     "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file:/h",
     "file | [11] | [12] | [13] | [14] | [15] | /h | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file:/",
     "file | [11] | [12] | [13] | [14] | [15] | | [16] | [17]",
     0, 0, FETCHUE_BAD_FILE_URL},
    {"file://127.0.0.1/hello.html",
     "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file:////hello.html",
     "file | [11] | [12] | [13] | [14] | [15] | //hello.html | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"file:///hello.html",
     "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
     0, 0, FETCHUE_OK},
    {"https://127.0.0.1",
     "https | [11] | [12] | [13] | 127.0.0.1 | 443 | / | [16] | [17]",
     0, FETCHU_DEFAULT_PORT, FETCHUE_OK},
    {"https://127.0.0.1",
     "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://[::1]:1234",
     "https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://127abc.com",
     "https | [11] | [12] | [13] | 127abc.com | [15] | / | [16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https:// example.com?check", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://e x a m p l e.com?check", "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {"https://example.com?check",
     "https | [11] | [12] | [13] | example.com | [15] | / | check | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com:65536",
     "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_BAD_PORT_NUMBER},
    {"https://example.com:-1#moo",
     "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_BAD_PORT_NUMBER},
    {"https://example.com:0#moo",
     "https | [11] | [12] | [13] | example.com | 0 | / | "
     "[16] | moo",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com:01#moo",
     "https | [11] | [12] | [13] | example.com | 1 | / | "
     "[16] | moo",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://example.com:1#moo",
     "https | [11] | [12] | [13] | example.com | 1 | / | "
     "[16] | moo",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com#moo",
     "http | [11] | [12] | [13] | example.com | [15] | / | "
     "[16] | moo",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com",
     "http | [11] | [12] | [13] | example.com | [15] | / | "
     "[16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com/path/html",
     "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
     "[16] | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com/path/html?query=name",
     "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
     "query=name | [17]",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com/path/html?query=name#anchor",
     "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://example.com:1234/path/html?query=name#anchor",
     "http | [11] | [12] | [13] | example.com | 1234 | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http:///user:password@example.com:1234/path/html?query=name#anchor",
     "http | user | password | [13] | example.com | 1234 | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"https://user:password@example.com:1234/path/html?query=name#anchor",
     "https | user | password | [13] | example.com | 1234 | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http://user:password@example.com:1234/path/html?query=name#anchor",
     "http | user | password | [13] | example.com | 1234 | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http:/user:password@example.com:1234/path/html?query=name#anchor",
     "http | user | password | [13] | example.com | 1234 | /path/html | "
     "query=name | anchor",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"http:////user:password@example.com:1234/path/html?query=name#anchor",
     "",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_BAD_SLASHES},
    {NULL, NULL, 0, 0, FETCHUE_OK},
};

static const struct urltestcase get_url_list[] = {
    {"example.com",
     "example.com/",
     FETCHU_GUESS_SCHEME, FETCHU_NO_GUESS_SCHEME, FETCHUE_OK},
    {"http://user@example.com?#",
     "http://user@example.com/?#",
     0, FETCHU_GET_EMPTY, FETCHUE_OK},
    /* WHATWG disgrees, it wants "https:/0.0.0.0/" */
    {"https://0x.0x.0", "https://0x.0x.0/", 0, 0, FETCHUE_OK},

    {"https://example.com:000000000000000000000443/foo",
     "https://example.com/foo",
     0, FETCHU_NO_DEFAULT_PORT, FETCHUE_OK},
    {"https://example.com:000000000000000000000/foo",
     "https://example.com:0/foo",
     0, FETCHU_NO_DEFAULT_PORT, FETCHUE_OK},
    {"https://192.0x0000A80001", "https://192.168.0.1/", 0, 0, FETCHUE_OK},
    {"https://0xffffffff", "https://255.255.255.255/", 0, 0, FETCHUE_OK},
    {"https://1.0x1000000", "https://1.0x1000000/", 0, 0, FETCHUE_OK},
    {"https://0x7f.1", "https://127.0.0.1/", 0, 0, FETCHUE_OK},
    {"https://1.2.3.256.com", "https://1.2.3.256.com/", 0, 0, FETCHUE_OK},
    {"https://10.com", "https://10.com/", 0, 0, FETCHUE_OK},
    {"https://1.2.com", "https://1.2.com/", 0, 0, FETCHUE_OK},
    {"https://1.2.3.com", "https://1.2.3.com/", 0, 0, FETCHUE_OK},
    {"https://1.2.com.99", "https://1.2.com.99/", 0, 0, FETCHUE_OK},
    {"https://[fe80::0000:20c:29ff:fe9c:409b]:80/moo",
     "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
     0, 0, FETCHUE_OK},
    {"https://[fe80::020c:29ff:fe9c:409b]:80/moo",
     "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
     0, 0, FETCHUE_OK},
    {"https://[fe80:0000:0000:0000:020c:29ff:fe9c:409b]:80/moo",
     "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
     0, 0, FETCHUE_OK},
    {"https://[fe80:0:0:0:409b::]:80/moo",
     "https://[fe80::409b:0:0:0]:80/moo",
     0, 0, FETCHUE_OK},
    /* normalize to lower case */
    {"https://[FE80:0:A:0:409B:0:0:0]:80/moo",
     "https://[fe80:0:a:0:409b::]:80/moo",
     0, 0, FETCHUE_OK},
    {"https://[::%25fakeit];80/moo",
     "",
     0, 0, FETCHUE_BAD_PORT_NUMBER},
    {"https://[fe80::20c:29ff:fe9c:409b]-80/moo",
     "",
     0, 0, FETCHUE_BAD_PORT_NUMBER},
#ifdef USE_IDN
    {"https://räksmörgås.se/path?q#frag",
     "https://xn--rksmrgs-5wao1o.se/path?q#frag", 0, FETCHU_PUNYCODE, FETCHUE_OK},
#endif
    /* unsupported schemes with no guessing enabled */
    {"data:text/html;charset=utf-8;base64,PCFET0NUWVBFIEhUTUw+PG1ldGEgY",
     "", 0, 0, FETCHUE_UNSUPPORTED_SCHEME},
    {"d:anything-really", "", 0, 0, FETCHUE_UNSUPPORTED_SCHEME},
    {"about:config", "", 0, 0, FETCHUE_UNSUPPORTED_SCHEME},
    {"example://foo", "", 0, 0, FETCHUE_UNSUPPORTED_SCHEME},
    {"mailto:infobot@example.com?body=send%20current-issue", "", 0, 0,
     FETCHUE_UNSUPPORTED_SCHEME},
    {"about:80", "https://about:80/", FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    /* percent encoded host names */
    {"http://example.com%40127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%21127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%3f127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%23127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%3a127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%09127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"http://example.com%2F127.0.0.1/", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://%41", "https://A/", 0, 0, FETCHUE_OK},
    {"https://%20", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://%41%0d", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://%25", "", 0, 0, FETCHUE_BAD_HOSTNAME},
    {"https://_%c0_", "https://_\xC0_/", 0, 0, FETCHUE_OK},
    {"https://_%c0_", "https://_%C0_/", 0, FETCHU_URLENCODE, FETCHUE_OK},

    /* IPv4 trickeries */
    {"https://16843009", "https://1.1.1.1/", 0, 0, FETCHUE_OK},
    {"https://0177.1", "https://127.0.0.1/", 0, 0, FETCHUE_OK},
    {"https://0111.02.0x3", "https://73.2.0.3/", 0, 0, FETCHUE_OK},
    {"https://0111.02.0x3.", "https://0111.02.0x3./", 0, 0, FETCHUE_OK},
    {"https://0111.02.030", "https://73.2.0.24/", 0, 0, FETCHUE_OK},
    {"https://0111.02.030.", "https://0111.02.030./", 0, 0, FETCHUE_OK},
    {"https://0xff.0xff.0377.255", "https://255.255.255.255/", 0, 0, FETCHUE_OK},
    {"https://1.0xffffff", "https://1.255.255.255/", 0, 0, FETCHUE_OK},
    /* IPv4 numerical overflows or syntax errors will not normalize */
    {"https://a127.0.0.1", "https://a127.0.0.1/", 0, 0, FETCHUE_OK},
    {"https://\xff.127.0.0.1", "https://%FF.127.0.0.1/", 0, FETCHU_URLENCODE,
     FETCHUE_OK},
    {"https://127.-0.0.1", "https://127.-0.0.1/", 0, 0, FETCHUE_OK},
    {"https://127.0. 1", "https://127.0.0.1/", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"https://1.2.3.256", "https://1.2.3.256/", 0, 0, FETCHUE_OK},
    {"https://1.2.3.256.", "https://1.2.3.256./", 0, 0, FETCHUE_OK},
    {"https://1.2.3.4.5", "https://1.2.3.4.5/", 0, 0, FETCHUE_OK},
    {"https://1.2.0x100.3", "https://1.2.0x100.3/", 0, 0, FETCHUE_OK},
    {"https://4294967296", "https://4294967296/", 0, 0, FETCHUE_OK},
    {"https://123host", "https://123host/", 0, 0, FETCHUE_OK},
    /* 40 bytes scheme is the max allowed */
    {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa://hostname/path",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    /* 41 bytes scheme is not allowed */
    {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
     "",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_BAD_SCHEME},
    {"https://[fe80::20c:29ff:fe9c:409b%]:1234",
     "",
     0, 0, FETCHUE_BAD_IPV6},
    {"https://[fe80::20c:29ff:fe9c:409b%25]:1234",
     "https://[fe80::20c:29ff:fe9c:409b%2525]:1234/",
     0, 0, FETCHUE_OK},
    {"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234",
     "https://[fe80::20c:29ff:fe9c:409b%25eth0]:1234/",
     0, 0, FETCHUE_OK},
    {"https://[::%25fakeit]/moo",
     "https://[::%25fakeit]/moo",
     0, 0, FETCHUE_OK},
    {"smtp.example.com/path/html",
     "smtp://smtp.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"https.example.com/path/html",
     "http://https.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"dict.example.com/path/html",
     "dict://dict.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"pop3.example.com/path/html",
     "pop3://pop3.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ldap.example.com/path/html",
     "ldap://ldap.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"imap.example.com/path/html",
     "imap://imap.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ftp.example.com/path/html",
     "ftp://ftp.example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"example.com/path/html",
     "http://example.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"smtp.com/path/html",
     "smtp://smtp.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"dict.com/path/html",
     "dict://dict.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"pop3.com/path/html",
     "pop3://pop3.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ldap.com/path/html",
     "ldap://ldap.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"imap.com/path/html",
     "imap://imap.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ftp.com/path/html",
     "ftp://ftp.com/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"smtp/path/html",
     "http://smtp/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"dict/path/html",
     "http://dict/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"pop3/path/html",
     "http://pop3/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ldap/path/html",
     "http://ldap/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"imap/path/html",
     "http://imap/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"ftp/path/html",
     "http://ftp/path/html",
     FETCHU_GUESS_SCHEME, 0, FETCHUE_OK},
    {"HTTP://test/", "http://test/", 0, 0, FETCHUE_OK},
    {"http://HO0_-st..~./", "http://HO0_-st..~./", 0, 0, FETCHUE_OK},
    {"http:/@example.com: 123/", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"http:/@example.com:123 /", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"http:/@example.com:123a/", "", 0, 0, FETCHUE_BAD_PORT_NUMBER},
    {"http://host/file\r", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"http://host/file\n\x03", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    {"htt\x02://host/file", "",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_MALFORMED_INPUT},
    {" http://host/file", "", 0, 0, FETCHUE_MALFORMED_INPUT},
    /* here the password ends at the semicolon and options is 'word' */
    {"imap://user:pass;word@host/file",
     "imap://user:pass;word@host/file",
     0, 0, FETCHUE_OK},
    /* here the password has the semicolon */
    {"http://user:pass;word@host/file",
     "http://user:pass;word@host/file", 0, 0, FETCHUE_OK},
    {"file:///file.txt#moo", "file:///file.txt#moo", 0, 0, FETCHUE_OK},
    {"file:////file.txt", "file:////file.txt", 0, 0, FETCHUE_OK},
    {"file:///file.txt", "file:///file.txt", 0, 0, FETCHUE_OK},
    {"file:./", "file://", 0, 0, FETCHUE_OK},
    {"http://example.com/hello/../here",
     "http://example.com/hello/../here",
     FETCHU_PATH_AS_IS, 0, FETCHUE_OK},
    {"http://example.com/hello/../here",
     "http://example.com/here",
     0, 0, FETCHUE_OK},
    {"http://example.com:80",
     "http://example.com/",
     0, FETCHU_NO_DEFAULT_PORT, FETCHUE_OK},
    {"tp://example.com/path/html",
     "",
     0, 0, FETCHUE_UNSUPPORTED_SCHEME},
    {"http://hello:fool@example.com",
     "",
     FETCHU_DISALLOW_USER, 0, FETCHUE_USER_NOT_ALLOWED},
    {"http:/@example.com:123",
     "http://@example.com:123/",
     0, 0, FETCHUE_OK},
    {"http:/:password@example.com",
     "http://:password@example.com/",
     0, 0, FETCHUE_OK},
    {"http://user@example.com?#",
     "http://user@example.com/",
     0, 0, FETCHUE_OK},
    {"http://user@example.com?",
     "http://user@example.com/",
     0, 0, FETCHUE_OK},
    {"http://user@example.com#anchor",
     "http://user@example.com/#anchor",
     0, 0, FETCHUE_OK},
    {"example.com/path/html",
     "https://example.com/path/html",
     FETCHU_DEFAULT_SCHEME, 0, FETCHUE_OK},
    {"example.com/path/html",
     "",
     0, 0, FETCHUE_BAD_SCHEME},
    {"http://user:password@example.com:1234/path/html?query=name#anchor",
     "http://user:password@example.com:1234/path/html?query=name#anchor",
     0, 0, FETCHUE_OK},
    {"http://example.com:1234/path/html?query=name#anchor",
     "http://example.com:1234/path/html?query=name#anchor",
     0, 0, FETCHUE_OK},
    {"http://example.com/path/html?query=name#anchor",
     "http://example.com/path/html?query=name#anchor",
     0, 0, FETCHUE_OK},
    {"http://example.com/path/html?query=name",
     "http://example.com/path/html?query=name",
     0, 0, FETCHUE_OK},
    {"http://example.com/path/html",
     "http://example.com/path/html",
     0, 0, FETCHUE_OK},
    {"tp://example.com/path/html",
     "tp://example.com/path/html",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"custom-scheme://host?expected=test-good",
     "custom-scheme://host/?expected=test-good",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_OK},
    {"custom-scheme://?expected=test-bad",
     "",
     FETCHU_NON_SUPPORT_SCHEME, 0, FETCHUE_NO_HOST},
    {"custom-scheme://?expected=test-new-good",
     "custom-scheme:///?expected=test-new-good",
     FETCHU_NON_SUPPORT_SCHEME | FETCHU_NO_AUTHORITY, 0, FETCHUE_OK},
    {"custom-scheme://host?expected=test-still-good",
     "custom-scheme://host/?expected=test-still-good",
     FETCHU_NON_SUPPORT_SCHEME | FETCHU_NO_AUTHORITY, 0, FETCHUE_OK},
    {NULL, NULL, 0, 0, FETCHUE_OK}};

static int checkurl(const char *org, const char *url, const char *out)
{
  if (strcmp(out, url))
  {
    fprintf(stderr,
            "Org:    %s\n"
            "Wanted: %s\n"
            "Got   : %s\n",
            org, out, url);
    return 1;
  }
  return 0;
}

/* 1. Set the URL
   2. Set components
   3. Extract all components (not URL)
*/
static const struct setgetcase setget_parts_list[] = {
    {"https://example.com/",
     "query=\"\",",
     "https | [11] | [12] | [13] | example.com | [15] | / |  | [17]",
     0, 0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://example.com/",
     "fragment=\"\",",
     "https | [11] | [12] | [13] | example.com | [15] | / | [16] | ",
     0, 0, FETCHU_GET_EMPTY, FETCHUE_OK},
    {"https://example.com/",
     "query=\"\",",
     "https | [11] | [12] | [13] | example.com | [15] | / | [16] | [17]",
     0, 0, 0, FETCHUE_OK},
    {"https://example.com",
     "path=get,",
     "https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]",
     0, 0, 0, FETCHUE_OK},
    {"https://example.com",
     "path=/get,",
     "https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]",
     0, 0, 0, FETCHUE_OK},
    {"https://example.com",
     "path=g e t,",
     "https | [11] | [12] | [13] | example.com | [15] | /g%20e%20t | "
     "[16] | [17]",
     0, FETCHU_URLENCODE, 0, FETCHUE_OK},
    {NULL, NULL, NULL, 0, 0, 0, FETCHUE_OK}};

/* !checksrc! disable SPACEBEFORECOMMA 1 */
static const struct setcase set_parts_list[] = {
    {"https://example.com/",
     "host=%43url.se,",
     "https://%43url.se/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://example.com/",
     "host=%25url.se,",
     "",
     0, 0, FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/?param=value",
     "query=\"\",",
     "https://example.com/",
     0, FETCHU_APPENDQUERY | FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_OK},
    {"https://example.com/",
     "host=\"\",",
     "https://example.com/",
     0, FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/",
     "host=\"\",",
     "https://example.com/",
     0, 0, FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com",
     "path=get,",
     "https://example.com/get",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://example.com/",
     "scheme=ftp+-.123,",
     "ftp+-.123://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_OK},
    {"https://example.com/",
     "scheme=1234,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     "scheme=1http,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     "scheme=-ftp,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     "scheme=+ftp,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     "scheme=.ftp,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     "host=example.com%2fmoo,",
     "",
     0, /* get */
     0, /* set */
     FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/",
     "host=http://fake,",
     "",
     0, /* get */
     0, /* set */
     FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/",
     "host=test%,",
     "",
     0, /* get */
     0, /* set */
     FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/",
     "host=te st,",
     "",
     0, /* get */
     0, /* set */
     FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {"https://example.com/",
     "host=0xff,", /* '++' there's no automatic URL decode when setting this
                    part */
     "https://0xff/",
     0, /* get */
     0, /* set */
     FETCHUE_OK, FETCHUE_OK},

    {"https://example.com/",
     "query=Al2cO3tDkcDZ3EWE5Lh+LX8TPHs,", /* contains '+' */
     "https://example.com/?Al2cO3tDkcDZ3EWE5Lh%2bLX8TPHs",
     FETCHU_URLDECODE, /* decode on get */
     FETCHU_URLENCODE, /* encode on set */
     FETCHUE_OK, FETCHUE_OK},

    {"https://example.com/",
     /* Set a bad scheme *including* :// */
     "scheme=https://,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     /* Set a 41 bytes scheme. That's too long so the old scheme remains set. */
     "scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_BAD_SCHEME},
    {"https://example.com/",
     /* set a 40 bytes scheme */
     "scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,",
     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_OK},
    {"https://[::1%25fake]:1234/",
     "zoneid=NULL,",
     "https://[::1]:1234/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://host:1234/",
     "port=NULL,",
     "https://host/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://host:1234/",
     "port=\"\",",
     "https://host:1234/",
     0, 0, FETCHUE_OK, FETCHUE_BAD_PORT_NUMBER},
    {"https://host:1234/",
     "port=56 78,",
     "https://host:1234/",
     0, 0, FETCHUE_OK, FETCHUE_BAD_PORT_NUMBER},
    {"https://host:1234/",
     "port=0,",
     "https://host:0/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://host:1234/",
     "port=65535,",
     "https://host:65535/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://host:1234/",
     "port=65536,",
     "https://host:1234/",
     0, 0, FETCHUE_OK, FETCHUE_BAD_PORT_NUMBER},
    {"https://host/",
     "path=%4A%4B%4C,",
     "https://host/%4a%4b%4c",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://host/mooo?q#f",
     "path=NULL,query=NULL,fragment=NULL,",
     "https://host/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"https://user:secret@host/",
     "user=NULL,password=NULL,",
     "https://host/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {NULL,
     "scheme=https,user=   @:,host=foobar,",
     "https://%20%20%20%40%3a@foobar/",
     0, FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_OK},
    /* Setting a host name with spaces is not OK: */
    {NULL,
     "scheme=https,host=  ,path= ,user= ,password= ,query= ,fragment= ,",
     "[nothing]",
     0, FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_BAD_HOSTNAME},
    {NULL,
     "scheme=https,host=foobar,path=/this /path /is /here,",
     "https://foobar/this%20/path%20/is%20/here",
     0, FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_OK},
    {NULL,
     "scheme=https,host=foobar,path=\xc3\xa4\xc3\xb6\xc3\xbc,",
     "https://foobar/%c3%a4%c3%b6%c3%bc",
     0, FETCHU_URLENCODE, FETCHUE_OK, FETCHUE_OK},
    {"imap://user:secret;opt@host/",
     "options=updated,scheme=imaps,password=p4ssw0rd,",
     "imaps://user:p4ssw0rd;updated@host/",
     0, 0, FETCHUE_NO_HOST, FETCHUE_OK},
    {"imap://user:secret;optit@host/",
     "scheme=https,",
     "https://user:secret@host/",
     0, 0, FETCHUE_NO_HOST, FETCHUE_OK},
    {"file:///file#anchor",
     "scheme=https,host=example,",
     "https://example/file#anchor",
     0, 0, FETCHUE_NO_HOST, FETCHUE_OK},
    {NULL, /* start fresh! */
     "scheme=file,host=127.0.0.1,path=/no,user=anonymous,",
     "file:///no",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {NULL, /* start fresh! */
     "scheme=ftp,host=127.0.0.1,path=/no,user=anonymous,",
     "ftp://anonymous@127.0.0.1/no",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {NULL, /* start fresh! */
     "scheme=https,host=example.com,",
     "https://example.com/",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_OK},
    {"http://user:foo@example.com/path?query#frag",
     "fragment=changed,",
     "http://user:foo@example.com/path?query#changed",
     0, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com/",
     "scheme=foo,", /* not accepted */
     "http://example.com/",
     0, 0, FETCHUE_OK, FETCHUE_UNSUPPORTED_SCHEME},
    {"http://example.com/",
     "scheme=https,path=/hello,fragment=snippet,",
     "https://example.com/hello#snippet",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com:80",
     "user=foo,port=1922,",
     "http://foo@example.com:1922/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com:80",
     "user=foo,password=bar,",
     "http://foo:bar@example.com:80/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com:80",
     "user=foo,",
     "http://foo@example.com:80/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com",
     "host=www.example.com,",
     "http://www.example.com/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"http://example.com:80",
     "scheme=ftp,",
     "ftp://example.com:80/",
     0, 0, FETCHUE_OK, FETCHUE_OK},
    {"custom-scheme://host",
     "host=\"\",",
     "custom-scheme://host/",
     FETCHU_NON_SUPPORT_SCHEME, FETCHU_NON_SUPPORT_SCHEME, FETCHUE_OK,
     FETCHUE_BAD_HOSTNAME},
    {"custom-scheme://host",
     "host=\"\",",
     "custom-scheme:///",
     FETCHU_NON_SUPPORT_SCHEME, FETCHU_NON_SUPPORT_SCHEME | FETCHU_NO_AUTHORITY,
     FETCHUE_OK, FETCHUE_OK},

    {NULL, NULL, NULL, 0, 0, FETCHUE_OK, FETCHUE_OK}};

static FETCHUPart part2id(char *part)
{
  if (!strcmp("url", part))
    return FETCHUPART_URL;
  if (!strcmp("scheme", part))
    return FETCHUPART_SCHEME;
  if (!strcmp("user", part))
    return FETCHUPART_USER;
  if (!strcmp("password", part))
    return FETCHUPART_PASSWORD;
  if (!strcmp("options", part))
    return FETCHUPART_OPTIONS;
  if (!strcmp("host", part))
    return FETCHUPART_HOST;
  if (!strcmp("port", part))
    return FETCHUPART_PORT;
  if (!strcmp("path", part))
    return FETCHUPART_PATH;
  if (!strcmp("query", part))
    return FETCHUPART_QUERY;
  if (!strcmp("fragment", part))
    return FETCHUPART_FRAGMENT;
  if (!strcmp("zoneid", part))
    return FETCHUPART_ZONEID;
  return (FETCHUPart)9999; /* bad input => bad output */
}

static FETCHUcode updateurl(FETCHU *u, const char *cmd, unsigned int setflags)
{
  const char *p = cmd;
  FETCHUcode uc;

  /* make sure the last command ends with a comma too! */
  while (p)
  {
    char *e = strchr(p, ',');
    if (e)
    {
      size_t n = (size_t)(e - p);
      char buf[80];
      char part[80];
      char value[80];

      memset(part, 0, sizeof(part));   /* Avoid valgrind false positive. */
      memset(value, 0, sizeof(value)); /* Avoid valgrind false positive. */
      memcpy(buf, p, n);
      buf[n] = 0;
      if (2 == sscanf(buf, "%79[^=]=%79[^,]", part, value))
      {
        FETCHUPart what = part2id(part);
#if 0
        /* for debugging this */
        fprintf(stderr, "%s = \"%s\" [%d]\n", part, value, (int)what);
#endif
        if (what > FETCHUPART_ZONEID)
          fprintf(stderr, "UNKNOWN part '%s'\n", part);

        if (!strcmp("NULL", value))
          uc = fetch_url_set(u, what, NULL, setflags);
        else if (!strcmp("\"\"", value))
          uc = fetch_url_set(u, what, "", setflags);
        else
          uc = fetch_url_set(u, what, value, setflags);
        if (uc)
          return uc;
      }
      p = e + 1;
      continue;
    }
    break;
  }
  return FETCHUE_OK;
}

static const struct redircase set_url_list[] = {
    {"http://example.org#withs/ash", "/moo#frag",
     "http://example.org/moo#frag",
     0, 0, FETCHUE_OK},
    {"http://example.org/", "../path/././../././../moo",
     "http://example.org/moo",
     0, 0, FETCHUE_OK},

    {"http://example.org?bar/moo", "?weird",
     "http://example.org/?weird", 0, 0, FETCHUE_OK},
    {"http://example.org/foo?bar", "?weird",
     "http://example.org/foo?weird", 0, 0, FETCHUE_OK},
    {"http://example.org/foo", "?weird",
     "http://example.org/foo?weird", 0, 0, FETCHUE_OK},
    {"http://example.org", "?weird",
     "http://example.org/?weird", 0, 0, FETCHUE_OK},
    {"http://example.org/#original", "?weird#moo",
     "http://example.org/?weird#moo", 0, 0, FETCHUE_OK},

    {"http://example.org?bar/moo#yes/path", "#new/slash",
     "http://example.org/?bar/moo#new/slash", 0, 0, FETCHUE_OK},
    {"http://example.org/foo?bar", "#weird",
     "http://example.org/foo?bar#weird", 0, 0, FETCHUE_OK},
    {"http://example.org/foo?bar#original", "#weird",
     "http://example.org/foo?bar#weird", 0, 0, FETCHUE_OK},
    {"http://example.org/foo#original", "#weird",
     "http://example.org/foo#weird", 0, 0, FETCHUE_OK},
    {"http://example.org/#original", "#weird",
     "http://example.org/#weird", 0, 0, FETCHUE_OK},
    {"http://example.org#original", "#weird",
     "http://example.org/#weird", 0, 0, FETCHUE_OK},
    {"http://example.org/foo?bar", "moo?hey#weird",
     "http://example.org/moo?hey#weird", 0, 0, FETCHUE_OK},
    {"http://example.org/",
     "../path/././../../moo",
     "http://example.org/moo",
     0, 0, FETCHUE_OK},
    {"http://example.org/",
     "//example.org/../path/../../",
     "http://example.org/",
     0, 0, FETCHUE_OK},
    {"http://example.org/",
     "///example.org/../path/../../",
     "http://example.org/",
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     ":23",
     "http://example.org/foo/:23",
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "\\x",
     "http://example.org/foo/\\x",
     /* WHATWG disagrees */
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "#/",
     "http://example.org/foo/bar#/",
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "?/",
     "http://example.org/foo/bar?/",
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "#;?",
     "http://example.org/foo/bar#;?",
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "#",
     "http://example.org/foo/bar",
     /* This happens because the parser removes empty fragments */
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "?",
     "http://example.org/foo/bar",
     /* This happens because the parser removes empty queries */
     0, 0, FETCHUE_OK},
    {"http://example.org/foo/bar",
     "?#",
     "http://example.org/foo/bar",
     /* This happens because the parser removes empty queries and fragments */
     0, 0, FETCHUE_OK},
    {"http://example.com/please/../gimme/%TESTNUMBER?foobar#hello",
     "http://example.net/there/it/is/../../tes t case=/%TESTNUMBER0002? yes no",
     "http://example.net/there/tes%20t%20case=/%TESTNUMBER0002?+yes+no",
     0, FETCHU_URLENCODE | FETCHU_ALLOW_SPACE, FETCHUE_OK},
    {"http://local.test?redirect=http://local.test:80?-321",
     "http://local.test:80?-123",
     "http://local.test:80/?-123",
     0, FETCHU_URLENCODE | FETCHU_ALLOW_SPACE, FETCHUE_OK},
    {"http://local.test?redirect=http://local.test:80?-321",
     "http://local.test:80?-123",
     "http://local.test:80/?-123",
     0, 0, FETCHUE_OK},
    {"http://example.org/static/favicon/wikipedia.ico",
     "//fake.example.com/licenses/by-sa/3.0/",
     "http://fake.example.com/licenses/by-sa/3.0/",
     0, 0, FETCHUE_OK},
    {"https://example.org/static/favicon/wikipedia.ico",
     "//fake.example.com/licenses/by-sa/3.0/",
     "https://fake.example.com/licenses/by-sa/3.0/",
     0, 0, FETCHUE_OK},
    {"file://localhost/path?query#frag",
     "foo#another",
     "file:///foo#another",
     0, 0, FETCHUE_OK},
    {"http://example.com/path?query#frag",
     "https://two.example.com/bradnew",
     "https://two.example.com/bradnew",
     0, 0, FETCHUE_OK},
    {"http://example.com/path?query#frag",
     "../../newpage#foo",
     "http://example.com/newpage#foo",
     0, 0, FETCHUE_OK},
    {"http://user:foo@example.com/path?query#frag",
     "../../newpage",
     "http://user:foo@example.com/newpage",
     0, 0, FETCHUE_OK},
    {"http://user:foo@example.com/path?query#frag",
     "../newpage",
     "http://user:foo@example.com/newpage",
     0, 0, FETCHUE_OK},
    {"http://user:foo@example.com/path?query#frag",
     "http://?hi",
     "http:///?hi",
     0, FETCHU_NO_AUTHORITY, FETCHUE_OK},
    {NULL, NULL, NULL, 0, 0, FETCHUE_OK}};

static int set_url(void)
{
  int i;
  int error = 0;

  for (i = 0; set_url_list[i].in && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
      break;
    rc = fetch_url_set(urlp, FETCHUPART_URL, set_url_list[i].in,
                       set_url_list[i].urlflags);
    if (!rc)
    {
      rc = fetch_url_set(urlp, FETCHUPART_URL, set_url_list[i].set,
                         set_url_list[i].setflags);
      if (rc)
      {
        fprintf(stderr, "%s:%d Set URL %s returned %d (%s)\n",
                __FILE__, __LINE__, set_url_list[i].set,
                (int)rc, fetch_url_strerror(rc));
        error++;
      }
      else
      {
        char *url = NULL;
        rc = fetch_url_get(urlp, FETCHUPART_URL, &url, 0);
        if (rc)
        {
          fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                  __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
          error++;
        }
        else
        {
          if (checkurl(set_url_list[i].in, url, set_url_list[i].out))
          {
            error++;
          }
        }
        fetch_free(url);
      }
    }
    else if (rc != set_url_list[i].ucode)
    {
      fprintf(stderr, "Set URL\nin: %s\nreturned %d (expected %d)\n",
              set_url_list[i].in, (int)rc, set_url_list[i].ucode);
      error++;
    }
    fetch_url_cleanup(urlp);
  }
  return error;
}

/* 1. Set a URL
   2. Set one or more parts
   3. Extract and compare all parts - not the URL
*/
static int setget_parts(void)
{
  int i;
  int error = 0;

  for (i = 0; setget_parts_list[i].set && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
    {
      error++;
      break;
    }
    if (setget_parts_list[i].in)
      rc = fetch_url_set(urlp, FETCHUPART_URL, setget_parts_list[i].in,
                         setget_parts_list[i].urlflags);
    else
      rc = FETCHUE_OK;
    if (!rc)
    {
      char *url = NULL;
      FETCHUcode uc = updateurl(urlp, setget_parts_list[i].set,
                                setget_parts_list[i].setflags);

      if (uc != setget_parts_list[i].pcode)
      {
        fprintf(stderr, "updateurl\nin: %s\nreturned %d (expected %d)\n",
                setget_parts_list[i].set, (int)uc, setget_parts_list[i].pcode);
        error++;
      }
      if (!uc)
      {
        if (checkparts(urlp, setget_parts_list[i].set, setget_parts_list[i].out,
                       setget_parts_list[i].getflags))
          error++; /* add */
      }
      fetch_free(url);
    }
    else if (rc != FETCHUE_OK)
    {
      fprintf(stderr, "Set parts\nin: %s\nreturned %d (expected %d)\n",
              setget_parts_list[i].in, (int)rc, 0);
      error++;
    }
    fetch_url_cleanup(urlp);
  }
  return error;
}

static int set_parts(void)
{
  int i;
  int error = 0;

  for (i = 0; set_parts_list[i].set && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
    {
      error++;
      break;
    }
    if (set_parts_list[i].in)
      rc = fetch_url_set(urlp, FETCHUPART_URL, set_parts_list[i].in,
                         set_parts_list[i].urlflags);
    else
      rc = FETCHUE_OK;
    if (!rc)
    {
      char *url = NULL;
      FETCHUcode uc = updateurl(urlp, set_parts_list[i].set,
                                set_parts_list[i].setflags);

      if (uc != set_parts_list[i].pcode)
      {
        fprintf(stderr, "updateurl\nin: %s\nreturned %d (expected %d)\n",
                set_parts_list[i].set, (int)uc, set_parts_list[i].pcode);
        error++;
      }
      if (!uc)
      {
        /* only do this if it worked */
        rc = fetch_url_get(urlp, FETCHUPART_URL, &url, 0);

        if (rc)
        {
          fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                  __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
          error++;
        }
        else if (checkurl(set_parts_list[i].in, url, set_parts_list[i].out))
        {
          error++;
        }
      }
      fetch_free(url);
    }
    else if (rc != set_parts_list[i].ucode)
    {
      fprintf(stderr, "Set parts\nin: %s\nreturned %d (expected %d)\n",
              set_parts_list[i].in, (int)rc, set_parts_list[i].ucode);
      error++;
    }
    fetch_url_cleanup(urlp);
  }
  return error;
}

static int get_url(void)
{
  int i;
  int error = 0;
  for (i = 0; get_url_list[i].in && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
    {
      error++;
      break;
    }
    rc = fetch_url_set(urlp, FETCHUPART_URL, get_url_list[i].in,
                       get_url_list[i].urlflags);
    if (!rc)
    {
      char *url = NULL;
      rc = fetch_url_get(urlp, FETCHUPART_URL, &url, get_url_list[i].getflags);

      if (rc)
      {
        fprintf(stderr, "%s:%d returned %d (%s). URL: '%s'\n",
                __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc),
                get_url_list[i].in);
        error++;
      }
      else
      {
        if (checkurl(get_url_list[i].in, url, get_url_list[i].out))
        {
          error++;
        }
      }
      fetch_free(url);
    }
    if (rc != get_url_list[i].ucode)
    {
      fprintf(stderr, "Get URL\nin: %s\nreturned %d (expected %d)\n",
              get_url_list[i].in, (int)rc, get_url_list[i].ucode);
      error++;
    }
    fetch_url_cleanup(urlp);
  }
  return error;
}

static int get_parts(void)
{
  int i;
  int error = 0;
  for (i = 0; get_parts_list[i].in && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
    {
      error++;
      break;
    }
    rc = fetch_url_set(urlp, FETCHUPART_URL,
                       get_parts_list[i].in,
                       get_parts_list[i].urlflags);
    if (rc != get_parts_list[i].ucode)
    {
      fprintf(stderr, "Get parts\nin: %s\nreturned %d (expected %d)\n",
              get_parts_list[i].in, (int)rc, get_parts_list[i].ucode);
      error++;
    }
    else if (get_parts_list[i].ucode)
    {
      /* the expected error happened */
    }
    else if (checkparts(urlp, get_parts_list[i].in, get_parts_list[i].out,
                        get_parts_list[i].getflags))
      error++;
    fetch_url_cleanup(urlp);
  }
  return error;
}

static const struct querycase append_list[] = {
    {"HTTP://test/?s", "name=joe\x02", "http://test/?s&name=joe%02",
     0, FETCHU_URLENCODE, FETCHUE_OK},
    {"HTTP://test/?size=2#f", "name=joe=", "http://test/?size=2&name=joe%3d#f",
     0, FETCHU_URLENCODE, FETCHUE_OK},
    {"HTTP://test/?size=2#f", "name=joe doe",
     "http://test/?size=2&name=joe+doe#f",
     0, FETCHU_URLENCODE, FETCHUE_OK},
    {"HTTP://test/", "name=joe", "http://test/?name=joe", 0, 0, FETCHUE_OK},
    {"HTTP://test/?size=2", "name=joe", "http://test/?size=2&name=joe",
     0, 0, FETCHUE_OK},
    {"HTTP://test/?size=2&", "name=joe", "http://test/?size=2&name=joe",
     0, 0, FETCHUE_OK},
    {"HTTP://test/?size=2#f", "name=joe", "http://test/?size=2&name=joe#f",
     0, 0, FETCHUE_OK},
    {NULL, NULL, NULL, 0, 0, FETCHUE_OK}};

static int append(void)
{
  int i;
  int error = 0;
  for (i = 0; append_list[i].in && !error; i++)
  {
    FETCHUcode rc;
    FETCHU *urlp = fetch_url();
    if (!urlp)
    {
      error++;
      break;
    }
    rc = fetch_url_set(urlp, FETCHUPART_URL,
                       append_list[i].in,
                       append_list[i].urlflags);
    if (rc)
      error++;
    else
      rc = fetch_url_set(urlp, FETCHUPART_QUERY,
                         append_list[i].q,
                         append_list[i].qflags | FETCHU_APPENDQUERY);
    if (error)
      ;
    else if (rc != append_list[i].ucode)
    {
      fprintf(stderr, "Append\nin: %s\nreturned %d (expected %d)\n",
              append_list[i].in, (int)rc, append_list[i].ucode);
      error++;
    }
    else if (append_list[i].ucode)
    {
      /* the expected error happened */
    }
    else
    {
      char *url;
      rc = fetch_url_get(urlp, FETCHUPART_URL, &url, 0);
      if (rc)
      {
        fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
        error++;
      }
      else
      {
        if (checkurl(append_list[i].in, url, append_list[i].out))
        {
          error++;
        }
        fetch_free(url);
      }
    }
    fetch_url_cleanup(urlp);
  }
  return error;
}

static int scopeid(void)
{
  FETCHU *u = fetch_url();
  int error = 0;
  FETCHUcode rc;
  char *url;

  rc = fetch_url_set(u, FETCHUPART_URL,
                     "https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html", 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_set returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }

  rc = fetch_url_get(u, FETCHUPART_HOST, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_set(u, FETCHUPART_HOST, "[::1]", 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_set FETCHUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }

  rc = fetch_url_get(u, FETCHUPART_URL, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_set(u, FETCHUPART_HOST, "example.com", 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_set FETCHUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }

  rc = fetch_url_get(u, FETCHUPART_URL, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_set(u, FETCHUPART_HOST,
                     "[fe80::20c:29ff:fe9c:409b%25eth0]", 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_set FETCHUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }

  rc = fetch_url_get(u, FETCHUPART_URL, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_get(u, FETCHUPART_HOST, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_get(u, FETCHUPART_ZONEID, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_ZONEID returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  rc = fetch_url_set(u, FETCHUPART_ZONEID, "clown", 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_set FETCHUPART_ZONEID returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }

  rc = fetch_url_get(u, FETCHUPART_URL, &url, 0);
  if (rc != FETCHUE_OK)
  {
    fprintf(stderr, "%s:%d fetch_url_get FETCHUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, fetch_url_strerror(rc));
    error++;
  }
  else
  {
    fetch_free(url);
  }

  fetch_url_cleanup(u);

  return error;
}

static int get_nothing(void)
{
  FETCHU *u = fetch_url();
  if (u)
  {
    char *p;
    FETCHUcode rc;

    rc = fetch_url_get(u, FETCHUPART_SCHEME, &p, 0);
    if (rc != FETCHUE_NO_SCHEME)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_HOST, &p, 0);
    if (rc != FETCHUE_NO_HOST)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_USER, &p, 0);
    if (rc != FETCHUE_NO_USER)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_PASSWORD, &p, 0);
    if (rc != FETCHUE_NO_PASSWORD)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_OPTIONS, &p, 0);
    if (rc != FETCHUE_NO_OPTIONS)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_PATH, &p, 0);
    if (rc != FETCHUE_OK)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);
    else
      fetch_free(p);

    rc = fetch_url_get(u, FETCHUPART_QUERY, &p, 0);
    if (rc != FETCHUE_NO_QUERY)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_FRAGMENT, &p, 0);
    if (rc != FETCHUE_NO_FRAGMENT)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = fetch_url_get(u, FETCHUPART_ZONEID, &p, 0);
    if (rc != FETCHUE_NO_ZONEID)
      fprintf(stderr, "unexpected return code %u on line %u\n", (int)rc,
              __LINE__);

    fetch_url_cleanup(u);
  }
  return 0;
}

static const struct clearurlcase clear_url_list[] = {
    {FETCHUPART_SCHEME, "http", NULL, FETCHUE_NO_SCHEME},
    {FETCHUPART_USER, "user", NULL, FETCHUE_NO_USER},
    {FETCHUPART_PASSWORD, "password", NULL, FETCHUE_NO_PASSWORD},
    {FETCHUPART_OPTIONS, "options", NULL, FETCHUE_NO_OPTIONS},
    {FETCHUPART_HOST, "host", NULL, FETCHUE_NO_HOST},
    {FETCHUPART_ZONEID, "eth0", NULL, FETCHUE_NO_ZONEID},
    {FETCHUPART_PORT, "1234", NULL, FETCHUE_NO_PORT},
    {FETCHUPART_PATH, "/hello", "/", FETCHUE_OK},
    {FETCHUPART_QUERY, "a=b", NULL, FETCHUE_NO_QUERY},
    {FETCHUPART_FRAGMENT, "anchor", NULL, FETCHUE_NO_FRAGMENT},
    {FETCHUPART_URL, NULL, NULL, FETCHUE_OK},
};

static int clear_url(void)
{
  FETCHU *u = fetch_url();
  int i, error = 0;
  if (u)
  {
    char *p = NULL;
    FETCHUcode rc;

    for (i = 0; clear_url_list[i].in && !error; i++)
    {
      rc = fetch_url_set(u, clear_url_list[i].part, clear_url_list[i].in, 0);
      if (rc != FETCHUE_OK)
        fprintf(stderr, "unexpected return code line %u\n", __LINE__);

      rc = fetch_url_set(u, FETCHUPART_URL, NULL, 0);
      if (rc != FETCHUE_OK)
        fprintf(stderr, "unexpected return code line %u\n", __LINE__);

      rc = fetch_url_get(u, clear_url_list[i].part, &p, 0);
      if (rc != clear_url_list[i].ucode || (clear_url_list[i].out &&
                                            0 != strcmp(p, clear_url_list[i].out)))
      {

        fprintf(stderr, "unexpected return code line %u\n", __LINE__);
        error++;
      }
      if (rc == FETCHUE_OK)
        fetch_free(p);
    }
  }

  fetch_url_cleanup(u);

  return error;
}

static char total[128000];
static char bigpart[120000];

/*
 * verify ridiculous URL part sizes
 */
static int huge(void)
{
  const char *smallpart = "c";
  int i;
  FETCHU *urlp = fetch_url();
  FETCHUcode rc;
  FETCHUPart part[] = {
      FETCHUPART_SCHEME,
      FETCHUPART_USER,
      FETCHUPART_PASSWORD,
      FETCHUPART_HOST,
      FETCHUPART_PATH,
      FETCHUPART_QUERY,
      FETCHUPART_FRAGMENT};
  int error = 0;
  if (!urlp)
    return 1;
  bigpart[0] = '/'; /* for the path */
  memset(&bigpart[1], 'a', sizeof(bigpart) - 2);
  bigpart[sizeof(bigpart) - 1] = 0;

  for (i = 0; i < 7; i++)
  {
    char *partp;
    msnprintf(total, sizeof(total),
              "%s://%s:%s@%s/%s?%s#%s",
              (i == 0) ? &bigpart[1] : smallpart,
              (i == 1) ? &bigpart[1] : smallpart,
              (i == 2) ? &bigpart[1] : smallpart,
              (i == 3) ? &bigpart[1] : smallpart,
              (i == 4) ? &bigpart[1] : smallpart,
              (i == 5) ? &bigpart[1] : smallpart,
              (i == 6) ? &bigpart[1] : smallpart);
    rc = fetch_url_set(urlp, FETCHUPART_URL, total, FETCHU_NON_SUPPORT_SCHEME);
    if ((!i && (rc != FETCHUE_BAD_SCHEME)) ||
        (i && rc))
    {
      printf("URL %u: failed to parse [%s]\n", i, total);
      error++;
    }

    /* only extract if the parse worked */
    if (!rc)
    {
      fetch_url_get(urlp, part[i], &partp, 0);
      if (!partp || strcmp(partp, &bigpart[1 - (i == 4)]))
      {
        printf("URL %u part %u: failure\n", i, part[i]);
        error++;
      }
      fetch_free(partp);
    }
  }
  fetch_url_cleanup(urlp);
  return error;
}

static int urldup(void)
{
  const char *url[] = {
      "http://"
      "user:pwd@"
      "[2a04:4e42:e00::347%25eth0]"
      ":80"
      "/path"
      "?query"
      "#fraggie",
      "https://example.com",
      "https://user@example.com",
      "https://user.pwd@example.com",
      "https://user.pwd@example.com:1234",
      "https://example.com:1234",
      "example.com:1234",
      "https://user.pwd@example.com:1234/path?query#frag",
      NULL};
  FETCHU *copy = NULL;
  char *h_str = NULL, *copy_str = NULL;
  FETCHU *h = fetch_url();
  int i;

  if (!h)
    goto err;

  for (i = 0; url[i]; i++)
  {
    FETCHUcode rc = fetch_url_set(h, FETCHUPART_URL, url[i],
                                  FETCHU_GUESS_SCHEME);
    if (rc)
      goto err;
    copy = fetch_url_dup(h);

    rc = fetch_url_get(h, FETCHUPART_URL, &h_str, 0);
    if (rc)
      goto err;

    rc = fetch_url_get(copy, FETCHUPART_URL, &copy_str, 0);
    if (rc)
      goto err;

    if (strcmp(h_str, copy_str))
    {
      printf("Original:  %s\nParsed:    %s\nCopy:      %s\n",
             url[i], h_str, copy_str);
      goto err;
    }
    fetch_free(copy_str);
    fetch_free(h_str);
    fetch_url_cleanup(copy);
    copy_str = NULL;
    h_str = NULL;
    copy = NULL;
  }
  fetch_url_cleanup(h);
  return 0;
err:
  fetch_free(copy_str);
  fetch_free(h_str);
  fetch_url_cleanup(copy);
  fetch_url_cleanup(h);
  return 1;
}

FETCHcode test(char *URL)
{
  (void)URL; /* not used */

  if (urldup())
    return (FETCHcode)11;

  if (setget_parts())
    return (FETCHcode)10;

  if (get_url())
    return (FETCHcode)3;

  if (huge())
    return (FETCHcode)9;

  if (get_nothing())
    return (FETCHcode)7;

  if (scopeid())
    return (FETCHcode)6;

  if (append())
    return (FETCHcode)5;

  if (set_url())
    return (FETCHcode)1;

  if (set_parts())
    return (FETCHcode)2;

  if (get_parts())
    return (FETCHcode)4;

  if (clear_url())
    return (FETCHcode)8;

  printf("success\n");
  return FETCHE_OK;
}
