/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h" /* LAST include file */

struct part {
  int part;
  const char *name;
};


static int checkparts(CURLURL *u, const char *in, const char *wanted,
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
    {0, NULL}
  };
  buf[0] = 0;

  for(i = 0; parts[i].name; i++) {
    char *p = NULL;
    size_t n;
    rc = curl_url_get(u, parts[i].part, &p, getflags);
    if(!rc && p) {
      snprintf(bufp, len, "%s%s", buf[0]?" | ":"", p);
    }
    else
      snprintf(bufp, len, "%s[%d]", buf[0]?" | ":"", (int)rc);

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

struct setcase {
  const char *in;
  const char *set;
  const char *out;
  unsigned int urlflags;
  unsigned int setflags;
  CURLUcode ucode;
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

struct testcase list[] ={
  {"https://127.0.0.1:443",
   "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [17] | [18]",
   0, CURLURL_NO_DEFAULT_PORT, CURLURLE_OK},
  {"https://127.0.0.1",
   "https | [11] | [12] | [13] | 127.0.0.1 | 443 | / | [17] | [18]",
   0, CURLURL_DEFAULT_PORT, CURLURLE_OK},
  {"https://127.0.0.1",
   "https | [11] | [12] | [13] | 127.0.0.1 | [15] | / | [17] | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https://[::1]:1234",
   "https | [11] | [12] | [13] | [::1] | 1234 | / | [17] | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https://127abc.com",
   "https | [11] | [12] | [13] | 127abc.com | [15] | / | [17] | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https:// example.com?check",
   "",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_MALFORMED_INPUT},
  {"https://e x a m p l e.com?check",
   "",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_MALFORMED_INPUT},
  {"https://example.com?check",
   "https | [11] | [12] | [13] | example.com | [15] | / | check | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https://example.com:65536",
   "",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_BAD_PORT_NUMBER},
  {"https://example.com:0#moo",
   "",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_BAD_PORT_NUMBER},
  {"https://example.com:01#moo",
   "https | [11] | [12] | [13] | example.com | 1 | / | "
   "[17] | moo",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https://example.com:1#moo",
   "https | [11] | [12] | [13] | example.com | 1 | / | "
   "[17] | moo",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com#moo",
   "http | [11] | [12] | [13] | example.com | [15] | / | "
   "[17] | moo",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com",
   "http | [11] | [12] | [13] | example.com | [15] | / | "
   "[17] | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com/path/html",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "[17] | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com/path/html?query=name",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "query=name | [18]",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com/path/html?query=name#anchor",
   "http | [11] | [12] | [13] | example.com | [15] | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://example.com:1234/path/html?query=name#anchor",
   "http | [11] | [12] | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http:///user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"https://user:password@example.com:1234/path/html?query=name#anchor",
   "https | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http://user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http:/user:password@example.com:1234/path/html?query=name#anchor",
   "http | user | password | [13] | example.com | 1234 | /path/html | "
   "query=name | anchor",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"http:////user:password@example.com:1234/path/html?query=name#anchor",
   "",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_MALFORMED_INPUT},
  {NULL, NULL, 0, 0, CURLURLE_OK},
};

struct urltestcase urllist[] = {
  {"http://example.com:80",
   "http://example.com/",
   0, CURLURL_NO_DEFAULT_PORT, CURLURLE_OK},
  {"tp://example.com/path/html",
   "",
   0, 0, CURLURLE_UNSUPPORTED_SCHEME},
  {"http://hello:fool@example.com",
   "",
   CURLURL_DISALLOW_USER, 0, CURLURLE_USER_NOT_ALLOWED},
  {"http:/@example.com:123",
   "http://example.com:123/",
   0, 0, CURLURLE_OK},
  {"http:/:password@example.com",
   "http://:password@example.com/",
   0, 0, CURLURLE_OK},
  {"http://user@example.com?#",
   "http://user@example.com/",
   0, 0, CURLURLE_OK},
  {"http://user@example.com?",
   "http://user@example.com/",
   0, 0, CURLURLE_OK},
  {"http://user@example.com#anchor",
   "http://user@example.com/#anchor",
   0, 0, CURLURLE_OK},
  {"example.com/path/html",
   "https://example.com/path/html",
   CURLURL_DEFAULT_SCHEME, 0, CURLURLE_OK},
  {"example.com/path/html",
   "",
   0, 0, CURLURLE_MALFORMED_INPUT},
  {"http://user:password@example.com:1234/path/html?query=name#anchor",
   "http://user:password@example.com:1234/path/html?query=name#anchor",
   0, 0, CURLURLE_OK},
  {"http://example.com:1234/path/html?query=name#anchor",
   "http://example.com:1234/path/html?query=name#anchor",
   0, 0, CURLURLE_OK},
  {"http://example.com/path/html?query=name#anchor",
   "http://example.com/path/html?query=name#anchor",
   0, 0, CURLURLE_OK},
  {"http://example.com/path/html?query=name",
   "http://example.com/path/html?query=name",
   0, 0, CURLURLE_OK},
  {"http://example.com/path/html",
   "http://example.com/path/html",
   0, 0, CURLURLE_OK},
  {"tp://example.com/path/html",
   "tp://example.com/path/html",
   CURLURL_NON_SUPPORT_SCHEME, 0, CURLURLE_OK},
  {NULL, NULL, 0, 0, 0}
};

static int checkurl(const char *url, const char *out)
{
  if(strcmp(out, url)) {
    fprintf(stderr, "Wanted: %s\nGot   : %s\n",
            out, url);
    return 1;
  }
  return 0;
}


struct setcase setlist[] = {
  {"http://user:foo@example.com/path?query#frag",
   "fragment=changed,",
   "http://user:foo@example.com/path?query#changed",
   0, CURLURL_NON_SUPPORT_SCHEME, CURLURLE_OK},
  {"http://example.com/",
   "scheme=foo,", /* not accepted */
   "http://example.com/",
   0, 0, CURLURLE_OK},
  {"http://example.com/",
   "scheme=https,path=/hello,fragment=snippet,",
   "https://example.com/hello#snippet",
   0, 0, CURLURLE_OK},
  {"http://example.com:80",
   "user=foo,port=1922,",
   "http://foo@example.com:1922/",
   0, 0, CURLURLE_OK},
  {"http://example.com:80",
   "user=foo,password=bar,",
   "http://foo:bar@example.com:80/",
   0, 0, CURLURLE_OK},
  {"http://example.com:80",
   "user=foo,",
   "http://foo@example.com:80/",
   0, 0, CURLURLE_OK},
  {"http://example.com",
   "host=www.example.com,",
   "http://www.example.com/",
   0, 0, CURLURLE_OK},
  {"http://example.com:80",
   "scheme=ftp,",
   "ftp://example.com:80/",
   0, 0, CURLURLE_OK},
  {NULL, NULL, NULL, 0, 0, 0}
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
  return 9999; /* bad input => bad output */
}

static void updateurl(CURLURL *u, const char *cmd, unsigned int setflags)
{
  const char *p = cmd;
  char *e;
  char buf[80];
  char part[80];
  char value[80];

  /* make sure the last command ends with a comma too! */
  while((e = strchr(p, ','))) {
    size_t n = e-p;
    memcpy(buf, p, n);
    buf[n] = 0;
    if(2 == sscanf(buf, "%79[^=]=%79[^,]", part, value)) {
      CURLUPart what = part2id(part);
#if 0
      /* for debugging this */
      fprintf(stderr, "%s = %s [%d]\n", part, value, (int)what);
#endif
      curl_url_set(u, what, value, setflags);
    }
    p = e + 1;
  }

}

int test(char *URL)
{
  CURLUcode rc;
  CURLURL *urlp;
  int i;
  (void)URL; /* not used */

  for(i = 0; setlist[i].in; i++) {
    char *url = NULL;
    urlp = NULL;
    rc = curl_url((char *)setlist[i].in, &urlp, setlist[i].urlflags);
    if(!rc) {
      updateurl(urlp, setlist[i].set, setlist[i].setflags);

      rc = curl_url_get(urlp, CURLUPART_URL, &url, 0);

      if(checkurl(url, setlist[i].out)) {
        return 3;
      }
    }
    else if(rc != urllist[i].ucode) {
      fprintf(stderr, "in: %s\nreturned %d (expected %d)\n", urllist[i].in,
              (int)rc, urllist[i].ucode);
      return 4;
    }
    curl_free(url);
    curl_url_cleanup(urlp);
  }

  for(i = 0; urllist[i].in; i++) {
    char *url = NULL;
    urlp = NULL;
    rc = curl_url((char *)urllist[i].in, &urlp, urllist[i].urlflags);
    if(!rc) {
      rc = curl_url_get(urlp, CURLUPART_URL, &url, urllist[i].getflags);

      if(checkurl(url, urllist[i].out)) {
        return 3;
      }
    }
    else if(rc != urllist[i].ucode) {
      fprintf(stderr, "in: %s\nreturned %d (expected %d)\n", urllist[i].in,
              (int)rc, urllist[i].ucode);
      return 4;
    }
    curl_free(url);
    curl_url_cleanup(urlp);
  }

  for(i = 0; list[i].in; i++) {
    rc = curl_url((char *)list[i].in, &urlp, list[i].urlflags);
    if(rc != list[i].ucode) {
      fprintf(stderr, "in: %s\nreturned %d (expected %d)\n", list[i].in,
              (int)rc, list[i].ucode);
      return 1;
    }
    else if(list[i].ucode) {
      /* the expected error happened */
    }
    else if(checkparts(urlp, list[i].in, list[i].out, list[i].getflags))
      return 2;
    curl_url_cleanup(urlp);
  }

  printf("success\n");
  return 0;
}
