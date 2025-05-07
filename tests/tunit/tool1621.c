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
#include "curlcheck.h"

#include "urldata.h"
#include "url.h"

#include "memdebug.h" /* LAST include file */

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
}

#ifndef USE_XATTR
/* stripcredentials isn't available in this case */

UNITTEST_START
UNITTEST_STOP
#else

char *stripcredentials(const char *url);

struct checkthis {
  const char *input;
  const char *output;
};

static const struct checkthis tests[] = {
  { "ninja://foo@example.com", "(null)" },  /* unsupported scheme */
  { "pop3s://foo@example.com", "pop3s://example.com/" },
  { "ldap://foo@example.com", "ldap://example.com/" },
  { "https://foo@example.com", "https://example.com/" },
  { "https://localhost:45", "https://localhost:45/" },
  { "https://foo@localhost:45", "https://localhost:45/" },
  { "http://daniel:password@localhost", "http://localhost/" },
  { "http://daniel@localhost", "http://localhost/" },
  { "https://user:pass@localhost:45", "https://localhost:45/" },
  { "http://localhost/", "http://localhost/" },
  { "http://odd%40host/", "(null)" },  /* bad host */
  { "http://user@odd%40host/", "(null)" },  /* bad host */
  { "http://host/@path/", "http://host/@path/" },
  { "http://emptypw:@host/", "http://host/" },
  { "http://:emptyuser@host/", "http://host/" },
  { "http://odd%40user@host/", "http://host/" },
  { "http://only%40one%40host/", "(null)" },  /* bad host */
  { "http://odder%3auser@host/", "http://host/" },
  { NULL, NULL } /* end marker */
};

UNITTEST_START
{
  int i;

  for(i = 0; tests[i].input; i++) {
    const char *url = tests[i].input;
    char *stripped = stripcredentials(url);
    char *strippedstr = stripped ? stripped : "(null)";
    printf("Test %u got input \"%s\", output: \"%s\"\n",
           i, tests[i].input, strippedstr);

    fail_if(strcmp(tests[i].output, strippedstr), tests[i].output);
    curl_free(stripped);
  }
}
UNITTEST_STOP
#endif
