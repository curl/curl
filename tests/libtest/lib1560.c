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

/*
 * Note:
 *
 * Since the URL parser by default only accepts schemes that *this instance*
 * of libcurl supports, make sure that the test1560 file lists all the schemes
 * that this test will assume to be present!
 */

#include "test.h"
#if defined(USE_LIBIDN2) || defined(USE_WIN32_IDN) || defined(USE_APPLE_IDN)
#define USE_IDN
#endif

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h" /* LAST include file */

struct part {
  CURLUPart part;
  const char *name;
};


static int checkparts(CURLU *u, const char *in, const char *wanted,
                      unsigned int getflags)
{
  int i;
  CURLUcode rc;
  char buf[256];
  char *bufp = &buf[0];
  size_t len = sizeof(buf);
  struct part parts[] = {
    {CURLUPART_SCHEME, "scheme"},
    {CURLUPART_USER, "user"},
    {CURLUPART_PASSWORD, "password"},
    {CURLUPART_OPTIONS, "options"},
    {CURLUPART_HOST, "host"},
    {CURLUPART_PORT, "port"},
    {CURLUPART_PATH, "path"},
    {CURLUPART_QUERY, "query"},
    {CURLUPART_FRAGMENT, "fragment"},
    {CURLUPART_URL, NULL}
  };
  memset(buf, 0, sizeof(buf));

  for(i = 0; parts[i].name; i++) {
    char *p = NULL;
    size_t n;
    rc = curl_url_get(u, parts[i].part, &p, getflags);
    if(!rc && p) {
      msnprintf(bufp, len, "%s%s", buf[0]?" | ":"", p);
    }
    else
      msnprintf(bufp, len, "%s[%d]", buf[0]?" | ":"", (int)rc);

    n = strlen(bufp);
    bufp += n;
    len -= n;
    curl_free(p);
  }
  if(strcmp(buf, wanted)) {
    fprintf(stderr, "in: %s\nwanted: %s\ngot:    %s\n", in, wanted, buf);
    return 1;
  }
  return 0;
}

struct redircase {
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags;
  unsigned int setflags;
  CURLUcode ucode;
};

struct setcase {
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags;
  unsigned int setflags;
  CURLUcode ucode; /* for the main URL set */
  CURLUcode pcode; /* for updating parts */
};

struct setgetcase {
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags; /* for setting the URL */
  unsigned int setflags; /* for updating parts */
  unsigned int getflags; /* for getting parts */
  CURLUcode pcode; /* for updating parts */
};

struct testcase {
  const char *in;
  const char *out;
  unsigned int urlflags;
  unsigned int getflags;
  CURLUcode ucode;
};

struct urltestcase {
  const char *in;
  const char *out;
  unsigned int urlflags; /* pass to curl_url() */
  unsigned int getflags; /* pass to curl_url_get() */
  CURLUcode ucode;
};

struct querycase {
  const char *in;
  const char *q;
  const char *out;
  unsigned int urlflags; /* pass to curl_url() */
  unsigned int qflags; /* pass to curl_url_get() */
  CURLUcode ucode;
};

struct clearurlcase {
  CURLUPart part;
  const char *in;
  const char *out;
  CURLUcode ucode;
};

static const struct testcase get_parts_list[] ={
  {"curl.se",
   "[10] | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]",
   CURLU_GUESS_SCHEME, CURLU_NO_GUESS_SCHEME, CURLUE_OK},
  {"https://curl.se:0/#",
   "https | [11] | [12] | [13] | curl.se | 0 | / | [16] | ",
   0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://curl.se/#",
   "https | [11] | [12] | [13] | curl.se | [15] | / | [16] | ",
   0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://curl.se/?#",
   "https | [11] | [12] | [13] | curl.se | [15] | / |  | ",
   0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://curl.se/?",
   "https | [11] | [12] | [13] | curl.se | [15] | / |  | [17]",
   0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://curl.se/?",
   "https | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  {"https://curl.se/?#",
   "https | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  {"https://curl.se/#  ",
   "https | [11] | [12] | [13] | curl.se | [15] | / | [16] | %20%20",
   CURLU_URLENCODE|CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {" ", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {"1h://example.net", "", 0, 0, CURLUE_BAD_SCHEME},
  {"..://example.net", "", 0, 0, CURLUE_BAD_SCHEME},
  {"-ht://example.net", "", 0, 0, CURLUE_BAD_SCHEME},
  {"+ftp://example.net", "", 0, 0, CURLUE_BAD_SCHEME},
  {"hej.hej://example.net",
   "hej.hej | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"ht-tp://example.net",
   "ht-tp | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"ftp+more://example.net",
   "ftp+more | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"f1337://example.net",
   "f1337 | [11] | [12] | [13] | example.net | [15] | / | [16] | [17]",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"https://user@example.net?hello# space ",
   "https | user | [12] | [13] | example.net | [15] | / | hello | %20space%20",
   CURLU_ALLOW_SPACE|CURLU_URLENCODE, 0, CURLUE_OK},
  {"https://test%test", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example.com%252f%40@example.net",
   "https | example.com%2f@ | [12] | [13] | example.net | [15] | / "
   "| [16] | [17]",
   0, CURLU_URLDECODE, CURLUE_OK },
#ifdef USE_IDN
  {"https://räksmörgås.se",
   "https | [11] | [12] | [13] | xn--rksmrgs-5wao1o.se | "
   "[15] | / | [16] | [17]", 0, CURLU_PUNYCODE, CURLUE_OK},
  {"https://xn--rksmrgs-5wao1o.se",
   "https | [11] | [12] | [13] | räksmörgås.se | "
   "[15] | / | [16] | [17]", 0, CURLU_PUNY2IDN, CURLUE_OK},
#else
  {"https://räksmörgås.se",
   "https | [11] | [12] | [13] | [30] | [15] | / | [16] | [17]",
   0, CURLU_PUNYCODE, CURLUE_OK},
#endif
  /* https://ℂᵤⓇℒ。𝐒🄴 */
  {"https://"
   "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4",
   "https | [11] | [12] | [13] | ℂᵤⓇℒ。𝐒🄴 | [15] |"
   " / | [16] | [17]",
   0, 0, CURLUE_OK},
  {"https://"
   "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4",
   "https | [11] | [12] | [13] | "
   "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4 "
   "| [15] | / | [16] | [17]",
   0, CURLU_URLENCODE, CURLUE_OK},
  {"https://"
   "\xe2\x84\x82\xe1\xb5\xa4\xe2\x93\x87\xe2\x84\x92"
   "\xe3\x80\x82\xf0\x9d\x90\x92\xf0\x9f\x84\xb4",
   "https | [11] | [12] | [13] | "
   "%e2%84%82%e1%b5%a4%e2%93%87%e2%84%92%e3%80%82%f0%9d%90%92%f0%9f%84%b4 "
   "| [15] | / | [16] | [17]",
   0, CURLU_URLENCODE, CURLUE_OK},
  {"https://user@example.net?he l lo",
   "https | user | [12] | [13] | example.net | [15] | / | he+l+lo | [17]",
   CURLU_ALLOW_SPACE, CURLU_URLENCODE, CURLUE_OK},
  {"https://user@example.net?he l lo",
   "https | user | [12] | [13] | example.net | [15] | / | he l lo | [17]",
   CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"https://exam{}[]ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam{ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam}ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam]ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam\\ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam$ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam'ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam\"ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam^ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam`ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam*ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam<ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam>ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam=ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://exam;ple.net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example,net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example&net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example+net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example(net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example)net", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://example.net/}",
   "https | [11] | [12] | [13] | example.net | [15] | /} | [16] | [17]",
   0, 0, CURLUE_OK},

  /* blank user is blank */
  {"https://:password@example.net",
   "https |  | password | [13] | example.net | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  /* blank user + blank password */
  {"https://:@example.net",
   "https |  |  | [13] | example.net | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  /* user-only (no password) */
  {"https://user@example.net",
   "https | user | [12] | [13] | example.net | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
#ifdef USE_WEBSOCKETS
  {"ws://example.com/color/?green",
   "ws | [11] | [12] | [13] | example.com | [15] | /color/ | green |"
   " [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"wss://example.com/color/?green",
   "wss | [11] | [12] | [13] | example.com | [15] | /color/ | green |"
   " [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
#endif

  {"https://user:password@example.net/get?this=and#but frag then", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://user:password@example.net/get?this=and what", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://user:password@example.net/ge t?this=and-what", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://user:pass word@example.net/get?this=and-what", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://u ser:password@example.net/get?this=and-what", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"imap://user:pass;opt ion@server/path", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  /* no space allowed in scheme */
  {"htt ps://user:password@example.net/get?this=and-what", "",
   CURLU_NON_SUPPORT_SCHEME|CURLU_ALLOW_SPACE, 0, CURLUE_BAD_SCHEME},
  {"https://user:password@example.net/get?this=and what",
   "https | user | password | [13] | example.net | [15] | /get | "
   "this=and what | [17]",
   CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"https://user:password@example.net/ge t?this=and-what",
   "https | user | password | [13] | example.net | [15] | /ge t | "
   "this=and-what | [17]",
   CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"https://user:pass word@example.net/get?this=and-what",
   "https | user | pass word | [13] | example.net | [15] | /get | "
   "this=and-what | [17]",
   CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"https://u ser:password@example.net/get?this=and-what",
   "https | u ser | password | [13] | example.net | [15] | /get | "
   "this=and-what | [17]",
   CURLU_ALLOW_SPACE, 0, CURLUE_OK},
  {"https://user:password@example.net/ge t?this=and-what",
   "https | user | password | [13] | example.net | [15] | /ge%20t | "
   "this=and-what | [17]",
   CURLU_ALLOW_SPACE | CURLU_URLENCODE, 0, CURLUE_OK},
  {"[0:0:0:0:0:0:0:1]",
   "http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK },
  {"[::1]",
   "http | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK },
  {"[::]",
   "http | [11] | [12] | [13] | [::] | [15] | / | [16] | [17]",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK },
  {"https://[::1]",
   "https | [11] | [12] | [13] | [::1] | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK },
  {"user:moo@ftp.example.com/color/#green?no-red",
   "ftp | user | moo | [13] | ftp.example.com | [15] | /color/ | [16] | "
   "green?no-red",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK },
  {"ftp.user:moo@example.com/color/#green?no-red",
   "http | ftp.user | moo | [13] | example.com | [15] | /color/ | [16] | "
   "green?no-red",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK },
#ifdef _WIN32
  {"file:/C:\\programs\\foo",
   "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"file://C:\\programs\\foo",
   "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"file:///C:\\programs\\foo",
   "file | [11] | [12] | [13] | [14] | [15] | C:\\programs\\foo | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"file://host.example.com/Share/path/to/file.txt",
   "file | [11] | [12] | [13] | host.example.com | [15] | "
   "//host.example.com/Share/path/to/file.txt | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
#endif
  {"https://example.com/color/#green?no-red",
   "https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | "
   "green?no-red",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"https://example.com/color/#green#no-red",
   "https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | "
   "green#no-red",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"https://example.com/color/?green#no-red",
   "https | [11] | [12] | [13] | example.com | [15] | /color/ | green | "
   "no-red",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"https://example.com/#color/?green#no-red",
   "https | [11] | [12] | [13] | example.com | [15] | / | [16] | "
   "color/?green#no-red",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"https://example.#com/color/?green#no-red",
   "https | [11] | [12] | [13] | example. | [15] | / | [16] | "
   "com/color/?green#no-red",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK },
  {"http://[ab.be:1]/x", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_BAD_IPV6},
  {"http://[ab.be]/x", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_BAD_IPV6},
  /* URL without host name */
  {"http://a:b@/x", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_NO_HOST},
  {"boing:80",
   "https | [11] | [12] | [13] | boing | 80 | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME|CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"http://[fd00:a41::50]:8080",
   "http | [11] | [12] | [13] | [fd00:a41::50] | 8080 | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://[fd00:a41::50]/",
   "http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://[fd00:a41::50]",
   "http | [11] | [12] | [13] | [fd00:a41::50] | [15] | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://[::1%252]:1234",
   "https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},

  /* here's "bad" zone id */
  {"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234",
   "https | [11] | [12] | [13] | [fe80::20c:29ff:fe9c:409b] | 1234 "
   "| / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://127.0.0.1:443",
   "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]",
   0, CURLU_NO_DEFAULT_PORT, CURLUE_OK},
  {"http://%3a:%3a@ex4mple/%3f+?+%3f+%23#+%23%3f%g7",
   "http | : | : | [13] | ex4mple | [15] | /?+ |  ? # | +#?%g7",
   0, CURLU_URLDECODE, CURLUE_OK},
  {"http://%3a:%3a@ex4mple/%3f?%3f%35#%35%3f%g7",
   "http | %3a | %3a | [13] | ex4mple | [15] | /%3f | %3f%35 | %35%3f%g7",
   0, 0, CURLUE_OK},
  {"http://HO0_-st%41/",
   "http | [11] | [12] | [13] | HO0_-stA | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file://hello.html",
   "",
   0, 0, CURLUE_BAD_FILE_URL},
  {"http://HO0_-st/",
   "http | [11] | [12] | [13] | HO0_-st | [15] | / | [16] | [17]",
   0, 0, CURLUE_OK},
  {"imap://user:pass;option@server/path",
   "imap | user | pass | option | server | [15] | /path | [16] | [17]",
   0, 0, CURLUE_OK},
  {"http://user:pass;option@server/path",
   "http | user | pass;option | [13] | server | [15] | /path | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file:/hello.html",
   "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file:/h",
   "file | [11] | [12] | [13] | [14] | [15] | /h | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file:/",
   "file | [11] | [12] | [13] | [14] | [15] | | [16] | [17]",
   0, 0, CURLUE_BAD_FILE_URL},
  {"file://127.0.0.1/hello.html",
   "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file:////hello.html",
   "file | [11] | [12] | [13] | [14] | [15] | //hello.html | [16] | [17]",
   0, 0, CURLUE_OK},
  {"file:///hello.html",
   "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
   0, 0, CURLUE_OK},
  {"https://127.0.0.1",
   "https | [11] | [12] | [13] | 127.0.0.1 | 443 | / | [16] | [17]",
   0, CURLU_DEFAULT_PORT, CURLUE_OK},
  {"https://127.0.0.1",
   "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://[::1]:1234",
   "https | [11] | [12] | [13] | [::1] | 1234 | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://127abc.com",
   "https | [11] | [12] | [13] | 127abc.com | [15] | / | [16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https:// example.com?check", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://e x a m p l e.com?check", "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {"https://example.com?check",
   "https | [11] | [12] | [13] | example.com | [15] | / | check | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://example.com:65536",
   "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_BAD_PORT_NUMBER},
  {"https://example.com:-1#moo",
   "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_BAD_PORT_NUMBER},
  {"https://example.com:0#moo",
   "https | [11] | [12] | [13] | example.com | 0 | / | "
   "[16] | moo",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://example.com:01#moo",
   "https | [11] | [12] | [13] | example.com | 1 | / | "
   "[16] | moo",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://example.com:1#moo",
   "https | [11] | [12] | [13] | example.com | 1 | / | "
   "[16] | moo",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com#moo",
   "http | [11] | [12] | [13] | example.com | [15] | / | "
   "[16] | moo",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com",
   "http | [11] | [12] | [13] | example.com | [15] | / | "
   "[16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com/path/html",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "[16] | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com/path/html?query=name",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "query=name | [17]",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com/path/html?query=name#anchor",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://example.com:1234/path/html?query=name#anchor",
   "http | [11] | [12] | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http:///user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"https://user:password@example.com:1234/path/html?query=name#anchor",
   "https | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http://user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http:/user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"http:////user:password@example.com:1234/path/html?query=name#anchor",
   "",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_BAD_SLASHES},
  {NULL, NULL, 0, 0, CURLUE_OK},
};

static const struct urltestcase get_url_list[] = {
  {"example.com",
   "example.com/",
   CURLU_GUESS_SCHEME, CURLU_NO_GUESS_SCHEME, CURLUE_OK},
  {"http://user@example.com?#",
   "http://user@example.com/?#",
   0, CURLU_GET_EMPTY, CURLUE_OK},
  /* WHATWG disgrees, it wants "https:/0.0.0.0/" */
  {"https://0x.0x.0", "https://0x.0x.0/", 0, 0, CURLUE_OK},

  {"https://example.com:000000000000000000000443/foo",
   "https://example.com/foo",
   0, CURLU_NO_DEFAULT_PORT, CURLUE_OK},
  {"https://example.com:000000000000000000000/foo",
   "https://example.com:0/foo",
   0, CURLU_NO_DEFAULT_PORT, CURLUE_OK},
  {"https://192.0x0000A80001", "https://192.168.0.1/", 0, 0, CURLUE_OK},
  {"https://0xffffffff", "https://255.255.255.255/", 0, 0, CURLUE_OK},
  {"https://1.0x1000000", "https://1.0x1000000/", 0, 0, CURLUE_OK},
  {"https://0x7f.1", "https://127.0.0.1/", 0, 0, CURLUE_OK},
  {"https://1.2.3.256.com", "https://1.2.3.256.com/", 0, 0, CURLUE_OK},
  {"https://10.com", "https://10.com/", 0, 0, CURLUE_OK},
  {"https://1.2.com", "https://1.2.com/", 0, 0, CURLUE_OK},
  {"https://1.2.3.com", "https://1.2.3.com/", 0, 0, CURLUE_OK},
  {"https://1.2.com.99", "https://1.2.com.99/", 0, 0, CURLUE_OK},
  {"https://[fe80::0000:20c:29ff:fe9c:409b]:80/moo",
   "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
   0, 0, CURLUE_OK},
  {"https://[fe80::020c:29ff:fe9c:409b]:80/moo",
   "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
   0, 0, CURLUE_OK},
  {"https://[fe80:0000:0000:0000:020c:29ff:fe9c:409b]:80/moo",
   "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
   0, 0, CURLUE_OK},
  {"https://[fe80:0:0:0:409b::]:80/moo",
   "https://[fe80::409b:0:0:0]:80/moo",
   0, 0, CURLUE_OK},
  {"https://[::%25fakeit];80/moo",
   "",
   0, 0, CURLUE_BAD_PORT_NUMBER},
  {"https://[fe80::20c:29ff:fe9c:409b]-80/moo",
   "",
   0, 0, CURLUE_BAD_PORT_NUMBER},
#ifdef USE_IDN
  {"https://räksmörgås.se/path?q#frag",
   "https://xn--rksmrgs-5wao1o.se/path?q#frag", 0, CURLU_PUNYCODE, CURLUE_OK},
#endif
  /* unsupported schemes with no guessing enabled */
  {"data:text/html;charset=utf-8;base64,PCFET0NUWVBFIEhUTUw+PG1ldGEgY",
   "", 0, 0, CURLUE_UNSUPPORTED_SCHEME},
  {"d:anything-really", "", 0, 0, CURLUE_UNSUPPORTED_SCHEME},
  {"about:config", "", 0, 0, CURLUE_UNSUPPORTED_SCHEME},
  {"example://foo", "", 0, 0, CURLUE_UNSUPPORTED_SCHEME},
  {"mailto:infobot@example.com?body=send%20current-issue", "", 0, 0,
   CURLUE_UNSUPPORTED_SCHEME},
  {"about:80", "https://about:80/", CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  /* percent encoded host names */
  {"http://example.com%40127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%21127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%3f127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%23127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%3a127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%09127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"http://example.com%2F127.0.0.1/", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://%41", "https://A/", 0, 0, CURLUE_OK},
  {"https://%20", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://%41%0d", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://%25", "", 0, 0, CURLUE_BAD_HOSTNAME},
  {"https://_%c0_", "https://_\xC0_/", 0, 0, CURLUE_OK},
  {"https://_%c0_", "https://_%C0_/", 0, CURLU_URLENCODE, CURLUE_OK},

  /* IPv4 trickeries */
  {"https://16843009", "https://1.1.1.1/", 0, 0, CURLUE_OK},
  {"https://0177.1", "https://127.0.0.1/", 0, 0, CURLUE_OK},
  {"https://0111.02.0x3", "https://73.2.0.3/", 0, 0, CURLUE_OK},
  {"https://0111.02.0x3.", "https://0111.02.0x3./", 0, 0, CURLUE_OK},
  {"https://0111.02.030", "https://73.2.0.24/", 0, 0, CURLUE_OK},
  {"https://0111.02.030.", "https://0111.02.030./", 0, 0, CURLUE_OK},
  {"https://0xff.0xff.0377.255", "https://255.255.255.255/", 0, 0, CURLUE_OK},
  {"https://1.0xffffff", "https://1.255.255.255/", 0, 0, CURLUE_OK},
  /* IPv4 numerical overflows or syntax errors will not normalize */
  {"https://a127.0.0.1", "https://a127.0.0.1/", 0, 0, CURLUE_OK},
  {"https://\xff.127.0.0.1", "https://%FF.127.0.0.1/", 0, CURLU_URLENCODE,
   CURLUE_OK},
  {"https://127.-0.0.1", "https://127.-0.0.1/", 0, 0, CURLUE_OK},
  {"https://127.0. 1", "https://127.0.0.1/", 0, 0, CURLUE_MALFORMED_INPUT},
  {"https://1.2.3.256", "https://1.2.3.256/", 0, 0, CURLUE_OK},
  {"https://1.2.3.256.", "https://1.2.3.256./", 0, 0, CURLUE_OK},
  {"https://1.2.3.4.5", "https://1.2.3.4.5/", 0, 0, CURLUE_OK},
  {"https://1.2.0x100.3", "https://1.2.0x100.3/", 0, 0, CURLUE_OK},
  {"https://4294967296", "https://4294967296/", 0, 0, CURLUE_OK},
  {"https://123host", "https://123host/", 0, 0, CURLUE_OK},
  /* 40 bytes scheme is the max allowed */
  {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa://hostname/path",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  /* 41 bytes scheme is not allowed */
  {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path",
   "",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_BAD_SCHEME},
  {"https://[fe80::20c:29ff:fe9c:409b%]:1234",
   "",
   0, 0, CURLUE_BAD_IPV6},
  {"https://[fe80::20c:29ff:fe9c:409b%25]:1234",
   "https://[fe80::20c:29ff:fe9c:409b%2525]:1234/",
   0, 0, CURLUE_OK},
  {"https://[fe80::20c:29ff:fe9c:409b%eth0]:1234",
   "https://[fe80::20c:29ff:fe9c:409b%25eth0]:1234/",
   0, 0, CURLUE_OK},
  {"https://[::%25fakeit]/moo",
   "https://[::%25fakeit]/moo",
   0, 0, CURLUE_OK},
  {"smtp.example.com/path/html",
   "smtp://smtp.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"https.example.com/path/html",
   "http://https.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"dict.example.com/path/html",
   "dict://dict.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"pop3.example.com/path/html",
   "pop3://pop3.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ldap.example.com/path/html",
   "ldap://ldap.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"imap.example.com/path/html",
   "imap://imap.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ftp.example.com/path/html",
   "ftp://ftp.example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"example.com/path/html",
   "http://example.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"smtp.com/path/html",
   "smtp://smtp.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"dict.com/path/html",
   "dict://dict.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"pop3.com/path/html",
   "pop3://pop3.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ldap.com/path/html",
   "ldap://ldap.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"imap.com/path/html",
   "imap://imap.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ftp.com/path/html",
   "ftp://ftp.com/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"smtp/path/html",
   "http://smtp/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"dict/path/html",
   "http://dict/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"pop3/path/html",
   "http://pop3/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ldap/path/html",
   "http://ldap/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"imap/path/html",
   "http://imap/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"ftp/path/html",
   "http://ftp/path/html",
   CURLU_GUESS_SCHEME, 0, CURLUE_OK},
  {"HTTP://test/", "http://test/", 0, 0, CURLUE_OK},
  {"http://HO0_-st..~./", "http://HO0_-st..~./", 0, 0, CURLUE_OK},
  {"http:/@example.com: 123/", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {"http:/@example.com:123 /", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {"http:/@example.com:123a/", "", 0, 0, CURLUE_BAD_PORT_NUMBER},
  {"http://host/file\r", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {"http://host/file\n\x03", "", 0, 0, CURLUE_MALFORMED_INPUT},
  {"htt\x02://host/file", "",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_MALFORMED_INPUT},
  {" http://host/file", "", 0, 0, CURLUE_MALFORMED_INPUT},
  /* here the password ends at the semicolon and options is 'word' */
  {"imap://user:pass;word@host/file",
   "imap://user:pass;word@host/file",
   0, 0, CURLUE_OK},
  /* here the password has the semicolon */
  {"http://user:pass;word@host/file",
   "http://user:pass;word@host/file", 0, 0, CURLUE_OK},
  {"file:///file.txt#moo", "file:///file.txt#moo", 0, 0, CURLUE_OK},
  {"file:////file.txt", "file:////file.txt", 0, 0, CURLUE_OK},
  {"file:///file.txt", "file:///file.txt", 0, 0, CURLUE_OK},
  {"file:./", "file://", 0, 0, CURLUE_OK},
  {"http://example.com/hello/../here",
   "http://example.com/hello/../here",
   CURLU_PATH_AS_IS, 0, CURLUE_OK},
  {"http://example.com/hello/../here",
   "http://example.com/here",
   0, 0, CURLUE_OK},
  {"http://example.com:80",
   "http://example.com/",
   0, CURLU_NO_DEFAULT_PORT, CURLUE_OK},
  {"tp://example.com/path/html",
   "",
   0, 0, CURLUE_UNSUPPORTED_SCHEME},
  {"http://hello:fool@example.com",
   "",
   CURLU_DISALLOW_USER, 0, CURLUE_USER_NOT_ALLOWED},
  {"http:/@example.com:123",
   "http://@example.com:123/",
   0, 0, CURLUE_OK},
  {"http:/:password@example.com",
   "http://:password@example.com/",
   0, 0, CURLUE_OK},
  {"http://user@example.com?#",
   "http://user@example.com/",
   0, 0, CURLUE_OK},
  {"http://user@example.com?",
   "http://user@example.com/",
   0, 0, CURLUE_OK},
  {"http://user@example.com#anchor",
   "http://user@example.com/#anchor",
   0, 0, CURLUE_OK},
  {"example.com/path/html",
   "https://example.com/path/html",
   CURLU_DEFAULT_SCHEME, 0, CURLUE_OK},
  {"example.com/path/html",
   "",
   0, 0, CURLUE_BAD_SCHEME},
  {"http://user:password@example.com:1234/path/html?query=name#anchor",
   "http://user:password@example.com:1234/path/html?query=name#anchor",
   0, 0, CURLUE_OK},
  {"http://example.com:1234/path/html?query=name#anchor",
   "http://example.com:1234/path/html?query=name#anchor",
   0, 0, CURLUE_OK},
  {"http://example.com/path/html?query=name#anchor",
   "http://example.com/path/html?query=name#anchor",
   0, 0, CURLUE_OK},
  {"http://example.com/path/html?query=name",
   "http://example.com/path/html?query=name",
   0, 0, CURLUE_OK},
  {"http://example.com/path/html",
   "http://example.com/path/html",
   0, 0, CURLUE_OK},
  {"tp://example.com/path/html",
   "tp://example.com/path/html",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"custom-scheme://host?expected=test-good",
   "custom-scheme://host/?expected=test-good",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_OK},
  {"custom-scheme://?expected=test-bad",
   "",
   CURLU_NON_SUPPORT_SCHEME, 0, CURLUE_NO_HOST},
  {"custom-scheme://?expected=test-new-good",
   "custom-scheme:///?expected=test-new-good",
   CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY, 0, CURLUE_OK},
  {"custom-scheme://host?expected=test-still-good",
   "custom-scheme://host/?expected=test-still-good",
   CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY, 0, CURLUE_OK},
  {NULL, NULL, 0, 0, CURLUE_OK}
};

static int checkurl(const char *org, const char *url, const char *out)
{
  if(strcmp(out, url)) {
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
   0, 0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://example.com/",
   "fragment=\"\",",
   "https | [11] | [12] | [13] | example.com | [15] | / | [16] | ",
   0, 0, CURLU_GET_EMPTY, CURLUE_OK},
  {"https://example.com/",
   "query=\"\",",
   "https | [11] | [12] | [13] | example.com | [15] | / | [16] | [17]",
   0, 0, 0, CURLUE_OK},
  {"https://example.com",
   "path=get,",
   "https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]",
   0, 0, 0, CURLUE_OK},
  {"https://example.com",
   "path=/get,",
   "https | [11] | [12] | [13] | example.com | [15] | /get | [16] | [17]",
   0, 0, 0, CURLUE_OK},
  {"https://example.com",
   "path=g e t,",
   "https | [11] | [12] | [13] | example.com | [15] | /g%20e%20t | "
   "[16] | [17]",
   0, CURLU_URLENCODE, 0, CURLUE_OK},
  {NULL, NULL, NULL, 0, 0, 0, CURLUE_OK}
};

/* !checksrc! disable SPACEBEFORECOMMA 1 */
static const struct setcase set_parts_list[] = {
  {"https://example.com/",
   "host=%43url.se,",
   "https://%43url.se/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://example.com/",
   "host=%25url.se,",
   "",
   0, 0, CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/?param=value",
   "query=\"\",",
   "https://example.com/",
   0, CURLU_APPENDQUERY | CURLU_URLENCODE, CURLUE_OK, CURLUE_OK},
  {"https://example.com/",
   "host=\"\",",
   "https://example.com/",
   0, CURLU_URLENCODE, CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/",
   "host=\"\",",
   "https://example.com/",
   0, 0, CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com",
   "path=get,",
   "https://example.com/get",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://example.com/",
   "scheme=ftp+-.123,",
   "ftp+-.123://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_OK},
  {"https://example.com/",
   "scheme=1234,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   "scheme=1http,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   "scheme=-ftp,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   "scheme=+ftp,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   "scheme=.ftp,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   "host=example.com%2fmoo,",
   "",
   0, /* get */
   0, /* set */
   CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/",
   "host=http://fake,",
   "",
   0, /* get */
   0, /* set */
   CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/",
   "host=test%,",
   "",
   0, /* get */
   0, /* set */
   CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/",
   "host=te st,",
   "",
   0, /* get */
   0, /* set */
   CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {"https://example.com/",
   "host=0xff,", /* '++' there's no automatic URL decode when setting this
                  part */
   "https://0xff/",
   0, /* get */
   0, /* set */
   CURLUE_OK, CURLUE_OK},

  {"https://example.com/",
   "query=Al2cO3tDkcDZ3EWE5Lh+LX8TPHs,", /* contains '+' */
   "https://example.com/?Al2cO3tDkcDZ3EWE5Lh%2bLX8TPHs",
   CURLU_URLDECODE, /* decode on get */
   CURLU_URLENCODE, /* encode on set */
   CURLUE_OK, CURLUE_OK},

  {"https://example.com/",
   /* Set a bad scheme *including* :// */
   "scheme=https://,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   /* Set a 41 bytes scheme. That's too long so the old scheme remains set. */
   "scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_BAD_SCHEME},
  {"https://example.com/",
   /* set a 40 bytes scheme */
   "scheme=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,",
   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_OK},
  {"https://[::1%25fake]:1234/",
   "zoneid=NULL,",
   "https://[::1]:1234/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://host:1234/",
   "port=NULL,",
   "https://host/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://host:1234/",
   "port=\"\",",
   "https://host:1234/",
   0, 0, CURLUE_OK, CURLUE_BAD_PORT_NUMBER},
  {"https://host:1234/",
   "port=56 78,",
   "https://host:1234/",
   0, 0, CURLUE_OK, CURLUE_BAD_PORT_NUMBER},
  {"https://host:1234/",
   "port=0,",
   "https://host:0/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://host:1234/",
   "port=65535,",
   "https://host:65535/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://host:1234/",
   "port=65536,",
   "https://host:1234/",
   0, 0, CURLUE_OK, CURLUE_BAD_PORT_NUMBER},
  {"https://host/",
   "path=%4A%4B%4C,",
   "https://host/%4a%4b%4c",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://host/mooo?q#f",
   "path=NULL,query=NULL,fragment=NULL,",
   "https://host/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"https://user:secret@host/",
   "user=NULL,password=NULL,",
   "https://host/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {NULL,
   "scheme=https,user=   @:,host=foobar,",
   "https://%20%20%20%40%3a@foobar/",
   0, CURLU_URLENCODE, CURLUE_OK, CURLUE_OK},
  /* Setting a host name with spaces is not OK: */
  {NULL,
   "scheme=https,host=  ,path= ,user= ,password= ,query= ,fragment= ,",
   "[nothing]",
   0, CURLU_URLENCODE, CURLUE_OK, CURLUE_BAD_HOSTNAME},
  {NULL,
   "scheme=https,host=foobar,path=/this /path /is /here,",
   "https://foobar/this%20/path%20/is%20/here",
   0, CURLU_URLENCODE, CURLUE_OK, CURLUE_OK},
  {NULL,
   "scheme=https,host=foobar,path=\xc3\xa4\xc3\xb6\xc3\xbc,",
   "https://foobar/%c3%a4%c3%b6%c3%bc",
   0, CURLU_URLENCODE, CURLUE_OK, CURLUE_OK},
  {"imap://user:secret;opt@host/",
   "options=updated,scheme=imaps,password=p4ssw0rd,",
   "imaps://user:p4ssw0rd;updated@host/",
   0, 0, CURLUE_NO_HOST, CURLUE_OK},
  {"imap://user:secret;optit@host/",
   "scheme=https,",
   "https://user:secret@host/",
   0, 0, CURLUE_NO_HOST, CURLUE_OK},
  {"file:///file#anchor",
   "scheme=https,host=example,",
   "https://example/file#anchor",
   0, 0, CURLUE_NO_HOST, CURLUE_OK},
  {NULL, /* start fresh! */
   "scheme=file,host=127.0.0.1,path=/no,user=anonymous,",
   "file:///no",
   0, 0, CURLUE_OK, CURLUE_OK},
  {NULL, /* start fresh! */
   "scheme=ftp,host=127.0.0.1,path=/no,user=anonymous,",
   "ftp://anonymous@127.0.0.1/no",
   0, 0, CURLUE_OK, CURLUE_OK},
  {NULL, /* start fresh! */
   "scheme=https,host=example.com,",
   "https://example.com/",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_OK},
  {"http://user:foo@example.com/path?query#frag",
   "fragment=changed,",
   "http://user:foo@example.com/path?query#changed",
   0, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK, CURLUE_OK},
  {"http://example.com/",
   "scheme=foo,", /* not accepted */
   "http://example.com/",
   0, 0, CURLUE_OK, CURLUE_UNSUPPORTED_SCHEME},
  {"http://example.com/",
   "scheme=https,path=/hello,fragment=snippet,",
   "https://example.com/hello#snippet",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"http://example.com:80",
   "user=foo,port=1922,",
   "http://foo@example.com:1922/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"http://example.com:80",
   "user=foo,password=bar,",
   "http://foo:bar@example.com:80/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"http://example.com:80",
   "user=foo,",
   "http://foo@example.com:80/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"http://example.com",
   "host=www.example.com,",
   "http://www.example.com/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"http://example.com:80",
   "scheme=ftp,",
   "ftp://example.com:80/",
   0, 0, CURLUE_OK, CURLUE_OK},
  {"custom-scheme://host",
   "host=\"\",",
   "custom-scheme://host/",
   CURLU_NON_SUPPORT_SCHEME, CURLU_NON_SUPPORT_SCHEME, CURLUE_OK,
   CURLUE_BAD_HOSTNAME},
  {"custom-scheme://host",
   "host=\"\",",
   "custom-scheme:///",
   CURLU_NON_SUPPORT_SCHEME, CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY,
   CURLUE_OK, CURLUE_OK},

  {NULL, NULL, NULL, 0, 0, CURLUE_OK, CURLUE_OK}
};

static CURLUPart part2id(char *part)
{
  if(!strcmp("url", part))
    return CURLUPART_URL;
  if(!strcmp("scheme", part))
    return CURLUPART_SCHEME;
  if(!strcmp("user", part))
    return CURLUPART_USER;
  if(!strcmp("password", part))
    return CURLUPART_PASSWORD;
  if(!strcmp("options", part))
    return CURLUPART_OPTIONS;
  if(!strcmp("host", part))
    return CURLUPART_HOST;
  if(!strcmp("port", part))
    return CURLUPART_PORT;
  if(!strcmp("path", part))
    return CURLUPART_PATH;
  if(!strcmp("query", part))
    return CURLUPART_QUERY;
  if(!strcmp("fragment", part))
    return CURLUPART_FRAGMENT;
  if(!strcmp("zoneid", part))
    return CURLUPART_ZONEID;
  return (CURLUPart)9999; /* bad input => bad output */
}

static CURLUcode updateurl(CURLU *u, const char *cmd, unsigned int setflags)
{
  const char *p = cmd;
  CURLUcode uc;

  /* make sure the last command ends with a comma too! */
  while(p) {
    char *e = strchr(p, ',');
    if(e) {
      size_t n = (size_t)(e - p);
      char buf[80];
      char part[80];
      char value[80];

      memset(part, 0, sizeof(part)); /* Avoid valgrind false positive. */
      memset(value, 0, sizeof(value)); /* Avoid valgrind false positive. */
      memcpy(buf, p, n);
      buf[n] = 0;
      if(2 == sscanf(buf, "%79[^=]=%79[^,]", part, value)) {
        CURLUPart what = part2id(part);
#if 0
        /* for debugging this */
        fprintf(stderr, "%s = \"%s\" [%d]\n", part, value, (int)what);
#endif
        if(what > CURLUPART_ZONEID)
          fprintf(stderr, "UNKNOWN part '%s'\n", part);

        if(!strcmp("NULL", value))
          uc = curl_url_set(u, what, NULL, setflags);
        else if(!strcmp("\"\"", value))
          uc = curl_url_set(u, what, "", setflags);
        else
          uc = curl_url_set(u, what, value, setflags);
        if(uc)
          return uc;
      }
      p = e + 1;
      continue;
    }
    break;
  }
  return CURLUE_OK;
}

static const struct redircase set_url_list[] = {
  {"http://example.org/",
   "../path/././../../moo",
   "http://example.org/moo",
   0, 0, CURLUE_OK},
  {"http://example.org/",
   "//example.org/../path/../../",
   "http://example.org/",
   0, 0, CURLUE_OK},
  {"http://example.org/",
   "///example.org/../path/../../",
   "http://example.org/",
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   ":23",
   "http://example.org/foo/:23",
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "\\x",
   "http://example.org/foo/\\x",
   /* WHATWG disagrees */
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "#/",
   "http://example.org/foo/bar#/",
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "?/",
   "http://example.org/foo/bar?/",
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "#;?",
   "http://example.org/foo/bar#;?",
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "#",
   "http://example.org/foo/bar",
   /* This happens because the parser removes empty fragments */
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "?",
   "http://example.org/foo/bar",
   /* This happens because the parser removes empty queries */
   0, 0, CURLUE_OK},
  {"http://example.org/foo/bar",
   "?#",
   "http://example.org/foo/bar",
   /* This happens because the parser removes empty queries and fragments */
   0, 0, CURLUE_OK},
  {"http://example.com/please/../gimme/%TESTNUMBER?foobar#hello",
   "http://example.net/there/it/is/../../tes t case=/%TESTNUMBER0002? yes no",
   "http://example.net/there/tes%20t%20case=/%TESTNUMBER0002?+yes+no",
   0, CURLU_URLENCODE|CURLU_ALLOW_SPACE, CURLUE_OK},
  {"http://local.test?redirect=http://local.test:80?-321",
   "http://local.test:80?-123",
   "http://local.test:80/?-123",
   0, CURLU_URLENCODE|CURLU_ALLOW_SPACE, CURLUE_OK},
  {"http://local.test?redirect=http://local.test:80?-321",
   "http://local.test:80?-123",
   "http://local.test:80/?-123",
   0, 0, CURLUE_OK},
  {"http://example.org/static/favicon/wikipedia.ico",
   "//fake.example.com/licenses/by-sa/3.0/",
   "http://fake.example.com/licenses/by-sa/3.0/",
   0, 0, CURLUE_OK},
  {"https://example.org/static/favicon/wikipedia.ico",
   "//fake.example.com/licenses/by-sa/3.0/",
   "https://fake.example.com/licenses/by-sa/3.0/",
   0, 0, CURLUE_OK},
  {"file://localhost/path?query#frag",
   "foo#another",
   "file:///foo#another",
   0, 0, CURLUE_OK},
  {"http://example.com/path?query#frag",
   "https://two.example.com/bradnew",
   "https://two.example.com/bradnew",
   0, 0, CURLUE_OK},
  {"http://example.com/path?query#frag",
   "../../newpage#foo",
   "http://example.com/newpage#foo",
   0, 0, CURLUE_OK},
  {"http://user:foo@example.com/path?query#frag",
   "../../newpage",
   "http://user:foo@example.com/newpage",
   0, 0, CURLUE_OK},
  {"http://user:foo@example.com/path?query#frag",
   "../newpage",
   "http://user:foo@example.com/newpage",
   0, 0, CURLUE_OK},
  {"http://user:foo@example.com/path?query#frag",
   "http://?hi",
   "http:///?hi",
   0, CURLU_NO_AUTHORITY, CURLUE_OK},
  {NULL, NULL, NULL, 0, 0, CURLUE_OK}
};

static int set_url(void)
{
  int i;
  int error = 0;

  for(i = 0; set_url_list[i].in && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp)
      break;
    rc = curl_url_set(urlp, CURLUPART_URL, set_url_list[i].in,
                      set_url_list[i].urlflags);
    if(!rc) {
      rc = curl_url_set(urlp, CURLUPART_URL, set_url_list[i].set,
                        set_url_list[i].setflags);
      if(rc) {
        fprintf(stderr, "%s:%d Set URL %s returned %d (%s)\n",
                __FILE__, __LINE__, set_url_list[i].set,
                (int)rc, curl_url_strerror(rc));
        error++;
      }
      else {
        char *url = NULL;
        rc = curl_url_get(urlp, CURLUPART_URL, &url, 0);
        if(rc) {
          fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                  __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
          error++;
        }
        else {
          if(checkurl(set_url_list[i].in, url, set_url_list[i].out)) {
            error++;
          }
        }
        curl_free(url);
      }
    }
    else if(rc != set_url_list[i].ucode) {
      fprintf(stderr, "Set URL\nin: %s\nreturned %d (expected %d)\n",
              set_url_list[i].in, (int)rc, set_url_list[i].ucode);
      error++;
    }
    curl_url_cleanup(urlp);
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

  for(i = 0; setget_parts_list[i].set && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp) {
      error++;
      break;
    }
    if(setget_parts_list[i].in)
      rc = curl_url_set(urlp, CURLUPART_URL, setget_parts_list[i].in,
                        setget_parts_list[i].urlflags);
    else
      rc = CURLUE_OK;
    if(!rc) {
      char *url = NULL;
      CURLUcode uc = updateurl(urlp, setget_parts_list[i].set,
                               setget_parts_list[i].setflags);

      if(uc != setget_parts_list[i].pcode) {
        fprintf(stderr, "updateurl\nin: %s\nreturned %d (expected %d)\n",
                setget_parts_list[i].set, (int)uc, setget_parts_list[i].pcode);
        error++;
      }
      if(!uc) {
        if(checkparts(urlp, setget_parts_list[i].set, setget_parts_list[i].out,
                      setget_parts_list[i].getflags))
          error++;        /* add */
      }
      curl_free(url);
    }
    else if(rc != CURLUE_OK) {
      fprintf(stderr, "Set parts\nin: %s\nreturned %d (expected %d)\n",
              setget_parts_list[i].in, (int)rc, 0);
      error++;
    }
    curl_url_cleanup(urlp);
  }
  return error;
}

static int set_parts(void)
{
  int i;
  int error = 0;

  for(i = 0; set_parts_list[i].set && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp) {
      error++;
      break;
    }
    if(set_parts_list[i].in)
      rc = curl_url_set(urlp, CURLUPART_URL, set_parts_list[i].in,
                        set_parts_list[i].urlflags);
    else
      rc = CURLUE_OK;
    if(!rc) {
      char *url = NULL;
      CURLUcode uc = updateurl(urlp, set_parts_list[i].set,
                               set_parts_list[i].setflags);

      if(uc != set_parts_list[i].pcode) {
        fprintf(stderr, "updateurl\nin: %s\nreturned %d (expected %d)\n",
                set_parts_list[i].set, (int)uc, set_parts_list[i].pcode);
        error++;
      }
      if(!uc) {
        /* only do this if it worked */
        rc = curl_url_get(urlp, CURLUPART_URL, &url, 0);

        if(rc) {
          fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                  __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
          error++;
        }
        else if(checkurl(set_parts_list[i].in, url, set_parts_list[i].out)) {
          error++;
        }
      }
      curl_free(url);
    }
    else if(rc != set_parts_list[i].ucode) {
      fprintf(stderr, "Set parts\nin: %s\nreturned %d (expected %d)\n",
              set_parts_list[i].in, (int)rc, set_parts_list[i].ucode);
      error++;
    }
    curl_url_cleanup(urlp);
  }
  return error;
}

static int get_url(void)
{
  int i;
  int error = 0;
  for(i = 0; get_url_list[i].in && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp) {
      error++;
      break;
    }
    rc = curl_url_set(urlp, CURLUPART_URL, get_url_list[i].in,
                      get_url_list[i].urlflags);
    if(!rc) {
      char *url = NULL;
      rc = curl_url_get(urlp, CURLUPART_URL, &url, get_url_list[i].getflags);

      if(rc) {
        fprintf(stderr, "%s:%d returned %d (%s). URL: '%s'\n",
                __FILE__, __LINE__, (int)rc, curl_url_strerror(rc),
                get_url_list[i].in);
        error++;
      }
      else {
        if(checkurl(get_url_list[i].in, url, get_url_list[i].out)) {
          error++;
        }
      }
      curl_free(url);
    }
    if(rc != get_url_list[i].ucode) {
      fprintf(stderr, "Get URL\nin: %s\nreturned %d (expected %d)\n",
              get_url_list[i].in, (int)rc, get_url_list[i].ucode);
      error++;
    }
    curl_url_cleanup(urlp);
  }
  return error;
}

static int get_parts(void)
{
  int i;
  int error = 0;
  for(i = 0; get_parts_list[i].in && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp) {
      error++;
      break;
    }
    rc = curl_url_set(urlp, CURLUPART_URL,
                      get_parts_list[i].in,
                      get_parts_list[i].urlflags);
    if(rc != get_parts_list[i].ucode) {
      fprintf(stderr, "Get parts\nin: %s\nreturned %d (expected %d)\n",
              get_parts_list[i].in, (int)rc, get_parts_list[i].ucode);
      error++;
    }
    else if(get_parts_list[i].ucode) {
      /* the expected error happened */
    }
    else if(checkparts(urlp, get_parts_list[i].in, get_parts_list[i].out,
                       get_parts_list[i].getflags))
      error++;
    curl_url_cleanup(urlp);
  }
  return error;
}

static const struct querycase append_list[] = {
  {"HTTP://test/?s", "name=joe\x02", "http://test/?s&name=joe%02",
   0, CURLU_URLENCODE, CURLUE_OK},
  {"HTTP://test/?size=2#f", "name=joe=", "http://test/?size=2&name=joe%3d#f",
   0, CURLU_URLENCODE, CURLUE_OK},
  {"HTTP://test/?size=2#f", "name=joe doe",
   "http://test/?size=2&name=joe+doe#f",
   0, CURLU_URLENCODE, CURLUE_OK},
  {"HTTP://test/", "name=joe", "http://test/?name=joe", 0, 0, CURLUE_OK},
  {"HTTP://test/?size=2", "name=joe", "http://test/?size=2&name=joe",
   0, 0, CURLUE_OK},
  {"HTTP://test/?size=2&", "name=joe", "http://test/?size=2&name=joe",
   0, 0, CURLUE_OK},
  {"HTTP://test/?size=2#f", "name=joe", "http://test/?size=2&name=joe#f",
   0, 0, CURLUE_OK},
  {NULL, NULL, NULL, 0, 0, CURLUE_OK}
};

static int append(void)
{
  int i;
  int error = 0;
  for(i = 0; append_list[i].in && !error; i++) {
    CURLUcode rc;
    CURLU *urlp = curl_url();
    if(!urlp) {
      error++;
      break;
    }
    rc = curl_url_set(urlp, CURLUPART_URL,
                      append_list[i].in,
                      append_list[i].urlflags);
    if(rc)
      error++;
    else
      rc = curl_url_set(urlp, CURLUPART_QUERY,
                        append_list[i].q,
                        append_list[i].qflags | CURLU_APPENDQUERY);
    if(error)
      ;
    else if(rc != append_list[i].ucode) {
      fprintf(stderr, "Append\nin: %s\nreturned %d (expected %d)\n",
              append_list[i].in, (int)rc, append_list[i].ucode);
      error++;
    }
    else if(append_list[i].ucode) {
      /* the expected error happened */
    }
    else {
      char *url;
      rc = curl_url_get(urlp, CURLUPART_URL, &url, 0);
      if(rc) {
        fprintf(stderr, "%s:%d Get URL returned %d (%s)\n",
                __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
        error++;
      }
      else {
        if(checkurl(append_list[i].in, url, append_list[i].out)) {
          error++;
        }
        curl_free(url);
      }
    }
    curl_url_cleanup(urlp);
  }
  return error;
}

static int scopeid(void)
{
  CURLU *u = curl_url();
  int error = 0;
  CURLUcode rc;
  char *url;

  rc = curl_url_set(u, CURLUPART_URL,
                    "https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html", 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_set returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }

  rc = curl_url_get(u, CURLUPART_HOST, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_set(u, CURLUPART_HOST, "[::1]", 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_set CURLUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }

  rc = curl_url_get(u, CURLUPART_URL, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_set(u, CURLUPART_HOST, "example.com", 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_set CURLUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }

  rc = curl_url_get(u, CURLUPART_URL, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_set(u, CURLUPART_HOST,
                    "[fe80::20c:29ff:fe9c:409b%25eth0]", 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_set CURLUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }

  rc = curl_url_get(u, CURLUPART_URL, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_get(u, CURLUPART_HOST, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_HOST returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_get(u, CURLUPART_ZONEID, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_ZONEID returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  rc = curl_url_set(u, CURLUPART_ZONEID, "clown", 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_set CURLUPART_ZONEID returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }

  rc = curl_url_get(u, CURLUPART_URL, &url, 0);
  if(rc != CURLUE_OK) {
    fprintf(stderr, "%s:%d curl_url_get CURLUPART_URL returned %d (%s)\n",
            __FILE__, __LINE__, (int)rc, curl_url_strerror(rc));
    error++;
  }
  else {
    curl_free(url);
  }

  curl_url_cleanup(u);

  return error;
}

static int get_nothing(void)
{
  CURLU *u = curl_url();
  if(u) {
    char *p;
    CURLUcode rc;

    rc = curl_url_get(u, CURLUPART_SCHEME, &p, 0);
    if(rc != CURLUE_NO_SCHEME)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_HOST, &p, 0);
    if(rc != CURLUE_NO_HOST)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_USER, &p, 0);
    if(rc != CURLUE_NO_USER)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_PASSWORD, &p, 0);
    if(rc != CURLUE_NO_PASSWORD)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_OPTIONS, &p, 0);
    if(rc != CURLUE_NO_OPTIONS)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_PATH, &p, 0);
    if(rc != CURLUE_OK)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);
    else
      curl_free(p);

    rc = curl_url_get(u, CURLUPART_QUERY, &p, 0);
    if(rc != CURLUE_NO_QUERY)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_FRAGMENT, &p, 0);
    if(rc != CURLUE_NO_FRAGMENT)
      fprintf(stderr, "unexpected return code line %u\n", __LINE__);

    rc = curl_url_get(u, CURLUPART_ZONEID, &p, 0);
    if(rc != CURLUE_NO_ZONEID)
      fprintf(stderr, "unexpected return code %u on line %u\n", (int)rc,
              __LINE__);

    curl_url_cleanup(u);
  }
  return 0;
}

static const struct clearurlcase clear_url_list[] ={
  {CURLUPART_SCHEME, "http", NULL, CURLUE_NO_SCHEME},
  {CURLUPART_USER, "user", NULL, CURLUE_NO_USER},
  {CURLUPART_PASSWORD, "password", NULL, CURLUE_NO_PASSWORD},
  {CURLUPART_OPTIONS, "options", NULL, CURLUE_NO_OPTIONS},
  {CURLUPART_HOST, "host", NULL, CURLUE_NO_HOST},
  {CURLUPART_ZONEID, "eth0", NULL, CURLUE_NO_ZONEID},
  {CURLUPART_PORT, "1234", NULL, CURLUE_NO_PORT},
  {CURLUPART_PATH, "/hello", "/", CURLUE_OK},
  {CURLUPART_QUERY, "a=b", NULL, CURLUE_NO_QUERY},
  {CURLUPART_FRAGMENT, "anchor", NULL, CURLUE_NO_FRAGMENT},
  {CURLUPART_URL, NULL, NULL, CURLUE_OK},
};

static int clear_url(void)
{
  CURLU *u = curl_url();
  int i, error = 0;
  if(u) {
    char *p = NULL;
    CURLUcode rc;

    for(i = 0; clear_url_list[i].in && !error; i++) {
      rc = curl_url_set(u, clear_url_list[i].part, clear_url_list[i].in, 0);
      if(rc != CURLUE_OK)
        fprintf(stderr, "unexpected return code line %u\n", __LINE__);

      rc = curl_url_set(u, CURLUPART_URL, NULL, 0);
      if(rc != CURLUE_OK)
        fprintf(stderr, "unexpected return code line %u\n", __LINE__);

      rc = curl_url_get(u, clear_url_list[i].part, &p, 0);
      if(rc != clear_url_list[i].ucode || (clear_url_list[i].out &&
         0 != strcmp(p, clear_url_list[i].out))) {

        fprintf(stderr, "unexpected return code line %u\n", __LINE__);
        error++;
      }
      if(rc == CURLUE_OK)
        curl_free(p);
    }
  }

  curl_url_cleanup(u);

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
  CURLU *urlp = curl_url();
  CURLUcode rc;
  CURLUPart part[]= {
    CURLUPART_SCHEME,
    CURLUPART_USER,
    CURLUPART_PASSWORD,
    CURLUPART_HOST,
    CURLUPART_PATH,
    CURLUPART_QUERY,
    CURLUPART_FRAGMENT
  };
  int error = 0;
  if(!urlp)
    return 1;
  bigpart[0] = '/'; /* for the path */
  memset(&bigpart[1], 'a', sizeof(bigpart) - 2);
  bigpart[sizeof(bigpart) - 1] = 0;

  for(i = 0; i <  7; i++) {
    char *partp;
    msnprintf(total, sizeof(total),
              "%s://%s:%s@%s/%s?%s#%s",
              (i == 0)? &bigpart[1] : smallpart,
              (i == 1)? &bigpart[1] : smallpart,
              (i == 2)? &bigpart[1] : smallpart,
              (i == 3)? &bigpart[1] : smallpart,
              (i == 4)? &bigpart[1] : smallpart,
              (i == 5)? &bigpart[1] : smallpart,
              (i == 6)? &bigpart[1] : smallpart);
    rc = curl_url_set(urlp, CURLUPART_URL, total, CURLU_NON_SUPPORT_SCHEME);
    if((!i && (rc != CURLUE_BAD_SCHEME)) ||
       (i && rc)) {
      printf("URL %u: failed to parse [%s]\n", i, total);
      error++;
    }

    /* only extract if the parse worked */
    if(!rc) {
      curl_url_get(urlp, part[i], &partp, 0);
      if(!partp || strcmp(partp, &bigpart[1 - (i == 4)])) {
        printf("URL %u part %u: failure\n", i, part[i]);
        error++;
      }
      curl_free(partp);
    }
  }
  curl_url_cleanup(urlp);
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
    NULL
  };
  CURLU *copy = NULL;
  char *h_str = NULL, *copy_str = NULL;
  CURLU *h = curl_url();
  int i;

  if(!h)
    goto err;

  for(i = 0; url[i]; i++) {
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url[i],
                                CURLU_GUESS_SCHEME);
    if(rc)
      goto err;
    copy = curl_url_dup(h);

    rc = curl_url_get(h, CURLUPART_URL, &h_str, 0);
    if(rc)
      goto err;

    rc = curl_url_get(copy, CURLUPART_URL, &copy_str, 0);
    if(rc)
      goto err;

    if(strcmp(h_str, copy_str)) {
      printf("Original:  %s\nParsed:    %s\nCopy:      %s\n",
             url[i], h_str, copy_str);
      goto err;
    }
    curl_free(copy_str);
    curl_free(h_str);
    curl_url_cleanup(copy);
    copy_str = NULL;
    h_str = NULL;
    copy = NULL;
  }
  curl_url_cleanup(h);
  return 0;
err:
  curl_free(copy_str);
  curl_free(h_str);
  curl_url_cleanup(copy);
  curl_url_cleanup(h);
  return 1;
}

CURLcode test(char *URL)
{
  (void)URL; /* not used */

  if(urldup())
    return (CURLcode)11;

  if(setget_parts())
    return (CURLcode)10;

  if(get_url())
    return (CURLcode)3;

  if(huge())
    return (CURLcode)9;

  if(get_nothing())
    return (CURLcode)7;

  if(scopeid())
    return (CURLcode)6;

  if(append())
    return (CURLcode)5;

  if(set_url())
    return (CURLcode)1;

  if(set_parts())
    return (CURLcode)2;

  if(get_parts())
    return (CURLcode)4;

  if(clear_url())
    return (CURLcode)8;

  printf("success\n");
  return CURLE_OK;
}
