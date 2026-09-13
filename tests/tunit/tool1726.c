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
#include "tool_getparam.h"
#include "tool_paramhlp.h"

static CURLcode test_tool1726(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct check {
    const char *input;
    const char *expect;
  };

  static const struct check tests[] = {
    /* plain user:password embedded in the URL */
    {"http://user:pass@example.com/path",
     "http://*********@example.com/path"},
    /* user name only */
    {"http://user@example.com/",
     "http://****@example.com/"},
    /* IPv6 host literal in brackets */
    {"https://u:p@[::1]:8080/x?y=1",
     "https://***@[::1]:8080/x?y=1"},
    /* password only */
    {"http://:secret@example.com/",
     "http://*******@example.com/"},
    /* percent-encoded '@' inside the user name, real '@' is the separator */
    {"http://u%40h:pw@example.com/",
     "http://********@example.com/"},
    /* '@' in the query string must not be treated as a userinfo separator */
    {"http://example.com/path?to=a@b",
     "http://example.com/path?to=a@b"},
    /* '@' in the path */
    {"http://example.com/a@b",
     "http://example.com/a@b"},
    /* no credentials at all */
    {"http://example.com/",
     "http://example.com/"},
    /* non-HTTP scheme */
    {"ftp://user:pass@ftp.example.com/file",
     "ftp://*********@ftp.example.com/file"},
    /* no scheme - curl guesses one, userinfo still masked */
    {"user:pass@example.com/x",
     "*********@example.com/x"},
    /* a guessed scheme with "://" later in the path must not be mistaken
       for the scheme separator */
    {"user:pass@example.com/a://b",
     "*********@example.com/a://b"},
    /* the same, with the "://" in the query */
    {"user:pass@example.com/x?q=://z",
     "*********@example.com/x?q=://z"},
    /* curl reads this as the credentials "mailto" and "user" on the host
       example.com, so that is what gets masked */
    {"mailto:user@example.com",
     "***********@example.com"},
    /* unencoded '@' in the userinfo - curl rejects the URL, left untouched */
    {"http://us@er:pa@ss@example.com/",
     "http://us@er:pa@ss@example.com/"},
    /* a glob in the authority - curl rejects the URL, left untouched */
    {"http://user:pass@ex{1,2}.com/p",
     "http://user:pass@ex{1,2}.com/p"},
    /* not a URL - left untouched */
    {"this is not a url",
     "this is not a url"},
    /* empty string */
    {"",
     ""},
    /* malformed, unparsable - left untouched */
    {"http://",
     "http://"},
    {NULL, NULL}
  };
  const struct check *p;

  for(p = tests; p->input; p++) {
    char *buf = curlx_strdup(p->input);
    abort_unless(buf, "out of memory");
    mask_userinfo(buf);
    if(strcmp(buf, p->expect)) {
      curl_mprintf("mask_userinfo(\"%s\")\n"
                   "  expected \"%s\"\n"
                   "  but got  \"%s\"\n", p->input, p->expect, buf);
      fail("assertion failure");
    }
    curlx_free(buf);
  }

  /* a NULL argument must be handled without crashing */
  mask_userinfo(NULL);

  UNITTEST_END_SIMPLE
}
