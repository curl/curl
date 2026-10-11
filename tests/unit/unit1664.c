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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

static CURLcode t1664_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

static CURLcode test_unit1664(const char *arg)
{
  UNITTEST_BEGIN(t1664_setup())

  int i;

  {
    static const char * const single[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "\t",
      "\n",
      "",
      NULL
    };
    curl_mprintf("curlx_str_singlespace\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = curlx_str_singlespace(&line);
      curl_mprintf("%d: (\"%s\") %d, line %d\n",
                   i, orgline, rc, (int)(line - orgline));
    }
  }

  {
    static const char * const newl[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "\n",
      "\r",
      "\r\n",
      "\x0c",
      "",
      NULL
    };
    printf("curlx_str_newline\n");
    for(i = 0; newl[i]; i++) {
      const char *line = newl[i];
      const char *orgline = line;
      int rc = curlx_str_newline(&line);
      printf("%d: (%%%02x) %d, line %d\n",
/* Workaround for the expression erroneously returning the byte from the next
   address for inputs \n, \r and \r\n. Thus returning NUL, NUL, \n instead of
   the expected \n, \r, \r. */
#ifdef VS2019_WORKAROUND
                   i, (unsigned int)newl[i][0],
#else
                   i, (unsigned int)*orgline,
#endif
                   rc, (int)(line - orgline));
    }
  }

  UNITTEST_END(curl_global_cleanup())
}
