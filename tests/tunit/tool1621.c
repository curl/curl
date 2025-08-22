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

#include "tool_xattr.h"

#include "memdebug.h" /* LAST include file */

static CURLcode test_tool1621(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_XATTR  /* Required for stripcredentials() */

  struct checkthis {
    const char *input;
    const char *output;
  };

  static const struct checkthis tests[] = {
    { "ninja://foo@example.com", "(null)" },  /* unsupported scheme */
#if defined(USE_SSL) && !defined(CURL_DISABLE_POP3)
    { "pop3s://foo@example.com", "pop3s://example.com/" },
#endif
#ifndef CURL_DISABLE_LDAP
    { "ldap://foo@example.com", "ldap://example.com/" },
#endif
#if defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)
    { "https://foo@example.com", "https://example.com/" },
    { "https://localhost:45", "https://localhost:45/" },
    { "https://foo@localhost:45", "https://localhost:45/" },
    { "https://user:pass@localhost:45", "https://localhost:45/" },
#endif
#ifndef CURL_DISABLE_HTTP
    { "http://daniel:password@localhost", "http://localhost/" },
    { "http://daniel@localhost", "http://localhost/" },
    { "http://localhost/", "http://localhost/" },
    { "http://odd%40host/", "(null)" },  /* bad host */
    { "http://user@odd%40host/", "(null)" },  /* bad host */
    { "http://host/@path/", "http://host/@path/" },
    { "http://emptypw:@host/", "http://host/" },
    { "http://:emptyuser@host/", "http://host/" },
    { "http://odd%40user@host/", "http://host/" },
    { "http://only%40one%40host/", "(null)" },  /* bad host */
    { "http://odder%3auser@host/", "http://host/" },
#endif
    { NULL, NULL } /* end marker */
  };

  int i;

  for(i = 0; tests[i].input; i++) {
    const char *url = tests[i].input;
    char *stripped = stripcredentials(url);
    const char *strippedstr = stripped ? stripped : "(null)";
    printf("Test %u got input \"%s\", output: \"%s\", expected: \"%s\"\n",
           i, tests[i].input, strippedstr, tests[i].output);

    fail_if(strcmp(tests[i].output, strippedstr), tests[i].output);
    curl_free(stripped);
  }
#endif

  UNITTEST_END_SIMPLE
}
