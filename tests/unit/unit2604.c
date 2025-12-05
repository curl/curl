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
#include "vssh/vssh.h"

static CURLcode test_unit2604(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_SSH

  struct set {
    const char *cp;
    const char *expect; /* the returned content */
    const char *next;   /* what cp points to after the call */
    const char *home;
    CURLcode res;
  };

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif

/* 60 a's */
#define SA60 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
/* 540 a's */
#define SA540 SA60 SA60 SA60 SA60 SA60 SA60 SA60 SA60 SA60
  int i;
  const size_t too_long = 90720;
  struct set list[] = {
    { "-too-long-", "", "", "", CURLE_TOO_LARGE },
    { SA540 " c", SA540, "c", "/", CURLE_OK },
    { "\" " SA540 "\" c", " " SA540, "c", "/", CURLE_OK },
    { "a a", "a", "a", "/home/", CURLE_OK },
    { "b a", "b", "a", "/", CURLE_OK },
    { "a", "a", "", "/home/", CURLE_OK },
    { "b", "b", "", "/", CURLE_OK },
    { "\"foo bar\"\tb", "foo bar", "b", "/", CURLE_OK },
    { "/~/hej", "/home/user/hej", "", "/home/user", CURLE_OK },
    { "\"foo bar", "", "", "/", CURLE_QUOTE_ERROR },
    { "\"foo\\\"bar\" a", "foo\"bar", "a", "/", CURLE_OK },
    { "\"foo\\\'bar\" b", "foo\'bar", "b", "/", CURLE_OK },
    { "\"foo\\\\bar\" c", "foo\\bar", "c", "/", CURLE_OK },
    { "\"foo\\pbar\" c", "foo\\bar", "", "/", CURLE_QUOTE_ERROR },
    { "\"\" c", "", "", "", CURLE_QUOTE_ERROR },
    { "foo\"", "foo\"", "", "/", CURLE_OK },
    { "foo \"", "foo", "\"", "/", CURLE_OK },
    { "   \t\t   \t  ", "", "", "/", CURLE_QUOTE_ERROR },
    { "              ", "", "", "/", CURLE_QUOTE_ERROR },
    { "", "", "", "/", CURLE_QUOTE_ERROR },
    { "       \r \n  ", "\r", "\n  ", "/", CURLE_OK },
    { NULL, NULL, NULL, NULL, CURLE_OK }
  };

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

  char *cp0 = curlx_calloc(1, too_long + 1);
  fail_unless(cp0, "could not alloc too long value");
  memset(cp0, 'a', too_long);

  for(i = 0; list[i].home; i++) {
    char *path;
    const char *cp = i == 0 ? cp0 : list[i].cp;
    CURLcode res = Curl_get_pathname(&cp, &path, list[i].home);
    curl_mprintf("%u - Curl_get_pathname(\"%s\", ... \"%s\") == %u\n", i,
                 list[i].cp, list[i].home, list[i].res);
    if(res != list[i].res) {
      curl_mprintf("... returned %d\n", res);
      unitfail++;
    }
    if(!res) {
      if(cp && strcmp(cp, list[i].next)) {
        curl_mprintf("... cp points to '%s', not '%s' as expected \n",
                     cp, list[i].next);
        unitfail++;
      }
      if(path && strcmp(path, list[i].expect)) {
        curl_mprintf("... gave '%s', not '%s' as expected \n",
                     path, list[i].expect);
        unitfail++;
      }
      curl_free(path);
    }
  }

  curlx_free(cp0);

#endif

  UNITTEST_END_SIMPLE
}
